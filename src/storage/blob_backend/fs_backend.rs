//! Filesystem implementation of [`BlobBackend`]. This is what the server has
//! always done — the on-disk pool under `<data_dir>/blobs/`, sharded two
//! levels by the tail of the UUID and falling back to the flat layout for
//! blobs written by older versions — now behind a trait so a future operator
//! can swap it for [`super::S3Backend`] without code changes.
//!
//! The pathing logic is delegated to [`crate::api::jmap::blob_path`]. Keeping
//! the helpers there means a reader following a blob id to its file ends up
//! at the same module whether the caller is the on-disk backend, a test, or
//! an upgrade tool.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use uuid::Uuid;

use super::BlobBackend;
use super::BlobError;

/// `Send + Sync` future alias specific to this module, kept narrow so the
/// trait surface in `blob_backend.rs` does not grow boilerplate. Uses
/// `'static` because the `BlobBackend` methods take borrowed args that get
/// cloned into the `Arc<Inner>`-style state owned by the future; matches the
/// pattern `OvhProvider::upsert` uses.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobError>> + Send + 'a>>;

/// Internal state shared by every async call. Cloned into the `async move`
/// block so the future owns everything it needs (matching the
/// `OvhProvider::upsert` pattern: cheap inner state, `&self` only borrows
/// while it is alive).
struct Inner {
	data_dir: PathBuf,
}

/// The on-disk blob store.
///
/// Mirrors the pre-`[storage.blobs]` behaviour exactly: a payload under
/// `<data_dir>/blobs/ab/cd/<id>` (sharded by the tail of the id), with a
/// fallback to the flat layout for blobs written by older versions.
/// Reads find both; writes always go to the sharded layout, so an
/// existing flat blob becomes invisible as soon as a sharded copy lands.
pub struct FsBackend {
	inner: Arc<Inner>,
}

impl FsBackend {
	/// Build a backend rooted at `data_dir`. The directory is not created
	/// here; the first write does it, mirroring what the upload handler used
	/// to do (the `dirs::create_dir_all` call before `write`).
	pub fn new(data_dir: PathBuf) -> Self {
		FsBackend {
			inner: Arc::new(Inner { data_dir }),
		}
	}
}

impl BlobBackend for FsBackend {
	fn get(&self, id: Uuid, suffix: &str) -> BoxFuture<'static, Option<Vec<u8>>> {
		let suffix = suffix.to_string();
		let inner = self.inner.clone();
		Box::pin(async move {
			let path = crate::api::jmap::blob_path::read_path(&inner.data_dir, id, &suffix);
			match std::fs::read(&path) {
				Ok(bytes) => Ok(Some(bytes)),
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
				Err(error) => Err(BlobError::Io(error)),
			}
		})
	}

	fn put(&self, id: Uuid, suffix: &str, bytes: &[u8]) -> BoxFuture<'static, ()> {
		let suffix = suffix.to_string();
		let payload = bytes.to_vec();
		let inner = self.inner.clone();
		Box::pin(async move {
			// Always write to the sharded location; reads fall back to the
			// flat one for older data, so a never-sharded write is still
			// safe but writing flat would recreate the layout the upgrade was
			// meant to retire.
			let path = crate::api::jmap::blob_path::write_path(&inner.data_dir, id, &suffix);
			if let Some(parent) = path.parent() {
				std::fs::create_dir_all(parent)?;
			}
			std::fs::write(&path, &payload)?;
			Ok(())
		})
	}

	fn delete(&self, id: Uuid, suffix: &str) -> BoxFuture<'static, ()> {
		let suffix = suffix.to_string();
		let inner = self.inner.clone();
		Box::pin(async move {
			// Removing the sharded copy unconditionally is the right move:
			// anything older than the sharding change was written to the
			// flat path and would still be reachable through the fallback,
			// but a successful `put` since then has moved it. Walk both
			// copies so an operator who re-points at S3 and back to fs does
			// not leave a stale flat blob shadowing the sharded one.
			let sharded = crate::api::jmap::blob_path::write_path(&inner.data_dir, id, &suffix);
			let flat = crate::api::jmap::blob_path::blob_root(&inner.data_dir)
				.join(format!("{id}{suffix}"));
			for path in [sharded, flat] {
				match std::fs::remove_file(&path) {
					Ok(()) => {}
					Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
					Err(error) => return Err(BlobError::Io(error)),
				}
			}
			Ok(())
		})
	}

	fn list(&self) -> BoxFuture<'static, Vec<Uuid>> {
		let inner = self.inner.clone();
		Box::pin(async move {
			let walked = crate::api::jmap::blob_path::walk(&inner.data_dir);
			Ok(walked.into_iter().map(|(id, _)| id).collect())
		})
	}
}
