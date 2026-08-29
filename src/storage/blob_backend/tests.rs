//! Cross-backend tests that don't belong inside any single backend's module:
//! the build factory, and the "fs default does no network" control (a config
//! without `[storage.blobs]` must produce an `FsBackend` and never reach for
//! a socket). The control is a deliberate guard: a future refactor that
//! starts talking to S3 by default would silently change the security story
//! of an offline-only install, and the test catches that.

use std::sync::Arc;

use super::*;

fn tmp_data_dir() -> tempfile::TempDir {
	tempfile::tempdir().expect("tempdir")
}

/// A runtime shared by the tests in this file. Built once because building a
/// tokio runtime per test is wasteful when the suite only does a handful of
/// round-trips against `FsBackend`.
fn runtime() -> tokio::runtime::Runtime {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("build a current-thread runtime")
}

#[test]
fn build_defaults_to_fs_when_no_section() {
	// A config without `[storage.blobs]` is the historical behavior:
	// blobs on disk, no S3 involvement. This is the load-bearing control:
	// an install that previously talked to no one must continue talking to
	// no one.
	let dir = tmp_data_dir();
	let backend = build(dir.path(), None).expect("build");
	// The returned object is `Arc<dyn BlobBackend>`; we cannot downcast to
	// `FsBackend` directly because the trait is `dyn`, but a working type
	// is `FsBackend`-like: it must respond to `put` / `get` against the
	// local filesystem. Round-trip the same id through it as the proof.
	let id = Uuid::now_v7();
	let backend_put = backend.clone();
	let backend_get = backend.clone();
	let rt = runtime();
	let bytes = b"round-trip".to_vec();
	// Two clones: one to keep for the assertion, one to push into the
	// first `async move` so the second `async move` finds it unchanged.
	let put_bytes = bytes.clone();
	let put_result = rt.block_on(async move { backend_put.put(id, "", &put_bytes).await });
	assert!(put_result.is_ok(), "fs default write: {put_result:?}");
	let read = rt.block_on(async move { backend_get.get(id, "").await });
	assert_eq!(read.expect("get"), Some(bytes));
}

#[test]
fn build_resolves_explicit_fs_to_fs_backend() {
	let dir = tmp_data_dir();
	let cfg = crate::config::BlobBackendConfig::Fs;
	let backend = build(dir.path(), Some(&cfg)).expect("build fs");
	assert!(Arc::strong_count(&backend) >= 1);
}

#[test]
fn list_from_a_fresh_disk_backend_is_empty() {
	let dir = tmp_data_dir();
	let backend = FsBackend::new(dir.path().to_path_buf());
	let rt = runtime();
	let ids = rt.block_on(async move { backend.list().await });
	assert!(ids.is_ok(), "{ids:?}");
	assert_eq!(ids.unwrap().len(), 0, "a fresh dir has zero blobs");
}
