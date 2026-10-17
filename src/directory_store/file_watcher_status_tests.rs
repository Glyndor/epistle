//! The reload status the file watcher publishes for the CLI: written
//! when the watcher starts, rewritten after a reload, and kept fresh
//! on every other poll by a bare mtime update.
//!
//! Lives in a sibling so `file_watcher_tests.rs` stays under the
//! per-file code-line budget.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::{FileWatcher, reload_fingerprint};
use crate::directory_store::{AccountStore, ReloadStatus, read_reload_status};

fn open_store(dir: &Path) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
}

/// A data dir whose `accounts.toml` exists, so the status has a real
/// fingerprint to publish.
fn data_dir() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(dir.path().join("accounts.toml"), "").expect("write accounts.toml");
	dir
}

fn status_mtime(dir: &Path) -> SystemTime {
	std::fs::metadata(dir.join(ReloadStatus::FILENAME))
		.and_then(|meta| meta.modified())
		.expect("status mtime")
}

fn inode(path: &Path) -> u64 {
	use std::os::unix::fs::MetadataExt;
	std::fs::metadata(path).expect("status metadata").ino()
}

#[tokio::test]
async fn starting_the_watcher_publishes_the_loaded_state() {
	let dir = data_dir();
	let watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::new(open_store(dir.path())));
	// An interval far beyond the test: only the start can have written.
	let polling = watcher.spawn(Duration::from_secs(3600));
	let status = read_reload_status(dir.path());
	polling.abort();
	let status = status.expect("the status is written when the watcher starts");
	assert!(
		status.matches(
			"accounts.toml",
			reload_fingerprint(&dir.path().join("accounts.toml"))
		),
		"the start status must carry what the server loaded"
	);
}

#[test]
fn a_poll_without_changes_moves_the_status_mtime_and_keeps_its_content() {
	let dir = data_dir();
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::new(open_store(dir.path())));
	watcher.poll();
	let path = dir.path().join(ReloadStatus::FILENAME);
	let before = std::fs::read(&path).expect("status written by the first poll");
	let first_inode = inode(&path);
	let long_ago = SystemTime::now() - Duration::from_secs(600);
	std::fs::File::options()
		.write(true)
		.open(&path)
		.and_then(|file| file.set_modified(long_ago))
		.expect("age the status");
	watcher.poll();
	assert!(
		status_mtime(dir.path()) > long_ago + Duration::from_secs(500),
		"a poll must refresh the status mtime"
	);
	assert_eq!(
		std::fs::read(&path).expect("status"),
		before,
		"a poll with nothing to load must not change the status content"
	);
	assert_eq!(
		inode(&path),
		first_inode,
		"the refresh must update the file in place, not write a new one"
	);
}

#[test]
fn a_poll_that_loads_a_change_publishes_the_new_fingerprint() {
	let dir = data_dir();
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), Arc::new(open_store(dir.path())));
	watcher.poll();
	let accounts = dir.path().join("accounts.toml");
	crate::storage::write_secret(
		&accounts,
		b"[[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\npassword_hash = \"x\"\n",
	)
	.expect("rewrite accounts.toml");
	watcher.poll();
	let status = read_reload_status(dir.path()).expect("status");
	assert!(
		status.matches("accounts.toml", reload_fingerprint(&accounts)),
		"the status must carry the fingerprint the poll loaded"
	);
}
