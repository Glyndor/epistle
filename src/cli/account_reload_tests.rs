//! `epistle account …` waits for the running server to load the file
//! it just wrote. These tests stand in for the server by writing
//! `reload.status` by hand: a live status (fresh mtime) that carries
//! the write's fingerprint ends the wait at once, a live status that
//! does not carries the wait to its timeout and the note, and a stale
//! status (old mtime) reads as no server at all.
//!
//! Lives in a sibling so `account_reload.rs` stays under the per-file
//! code-line budget.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

use super::{NOT_LOADED_NOTE, Waited, wait_within, with_timeout};
use crate::cli::account::enable_with_store;
use crate::directory_store::file_watcher::Fingerprint;
use crate::directory_store::{AccountStore, DynamicAccount, ReloadStatus, reload_fingerprint};
use crate::smtp::auth::tests::{fixture_password, hash};

/// A data dir with one dynamic account, `bob`, in `accounts.toml`.
fn fixture() -> (tempfile::TempDir, AccountStore) {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	store
		.add(DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: hash(fixture_password()),
			..DynamicAccount::default()
		})
		.expect("add bob");
	(dir, store)
}

/// A fingerprint no real file has.
fn elsewhere() -> Option<Fingerprint> {
	Some(Fingerprint {
		mtime_secs: 1,
		len: 1,
		ino: 1,
	})
}

/// Write a status that says the server loaded `accounts` for
/// `accounts.toml`, with its mtime set `age` in the past.
fn write_status(data_dir: &Path, accounts: Option<Fingerprint>, age: Duration) {
	let mut status = ReloadStatus::default();
	status.files.insert("accounts.toml".to_string(), accounts);
	// Written aside and renamed into place, as the server writes it: a
	// plain write truncates first, and a wait polling at that moment reads
	// an empty status and returns as if no server were running.
	let path = data_dir.join(ReloadStatus::FILENAME);
	let staged = data_dir.join(format!("{}.staged", ReloadStatus::FILENAME));
	std::fs::write(&staged, serde_json::to_string(&status).expect("serialise")).expect("write");
	std::fs::File::options()
		.write(true)
		.open(&staged)
		.and_then(|file| file.set_modified(SystemTime::now() - age))
		.expect("set the status mtime");
	std::fs::rename(&staged, &path).expect("rename into place");
}

#[test]
fn stale_status_reads_as_no_server_and_returns_at_once() {
	let (dir, store) = fixture();
	// A server that stopped without removing its status, a minute ago,
	// before it could load anything new: the fingerprint does not match.
	write_status(dir.path(), elsewhere(), Duration::from_secs(60));
	let mut note = Vec::new();
	let start = Instant::now();
	let waited = wait_within(store.store_path(), &mut note, Duration::from_secs(3));
	assert_eq!(waited, Waited::NoServer);
	assert!(
		start.elapsed() < Duration::from_secs(1),
		"a stale status must not hold the command"
	);
	assert!(note.is_empty(), "no server, nothing to note");
}

#[test]
fn stale_status_lets_the_command_exit_zero_at_once() {
	let (dir, store) = fixture();
	write_status(dir.path(), elsewhere(), Duration::from_secs(60));
	let start = Instant::now();
	let code = with_timeout(Duration::from_secs(3), || {
		enable_with_store(&store, "bob", &mut std::io::sink(), false)
	});
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		start.elapsed() < Duration::from_secs(1),
		"a stale status must not hold the command"
	);
}

#[test]
fn live_status_with_the_written_fingerprint_returns_at_once() {
	let (dir, store) = fixture();
	write_status(
		dir.path(),
		reload_fingerprint(store.store_path()),
		Duration::ZERO,
	);
	let mut note = Vec::new();
	let start = Instant::now();
	let waited = wait_within(store.store_path(), &mut note, Duration::from_secs(3));
	assert_eq!(waited, Waited::Loaded);
	assert!(
		start.elapsed() < Duration::from_secs(1),
		"a matching status must end the wait"
	);
	assert!(note.is_empty(), "a loaded change needs no note");
}

#[test]
fn live_status_without_the_fingerprint_times_out_with_the_note() {
	let (dir, store) = fixture();
	write_status(dir.path(), elsewhere(), Duration::ZERO);
	let mut note = Vec::new();
	let start = Instant::now();
	let waited = wait_within(store.store_path(), &mut note, Duration::from_millis(300));
	assert_eq!(waited, Waited::TimedOut);
	assert!(
		start.elapsed() >= Duration::from_millis(300),
		"a live server that has not loaded the change must be waited for"
	);
	assert_eq!(
		String::from_utf8(note).expect("utf8"),
		format!("{NOT_LOADED_NOTE}\n")
	);
}

#[test]
fn a_timed_out_wait_still_exits_zero() {
	let (dir, store) = fixture();
	write_status(dir.path(), elsewhere(), Duration::ZERO);
	let start = Instant::now();
	let code = with_timeout(Duration::from_millis(300), || {
		enable_with_store(&store, "bob", &mut std::io::sink(), false)
	});
	assert!(
		start.elapsed() >= Duration::from_millis(300),
		"the command must have waited for the live server"
	);
	assert_eq!(
		code,
		ExitCode::SUCCESS,
		"the change is written; a retry would only fail"
	);
}

#[test]
fn a_status_that_arrives_during_the_wait_ends_it() {
	let (dir, store) = fixture();
	write_status(dir.path(), elsewhere(), Duration::ZERO);
	let target = reload_fingerprint(store.store_path());
	let data_dir = dir.path().to_path_buf();
	let poster = std::thread::spawn(move || {
		std::thread::sleep(Duration::from_millis(200));
		write_status(&data_dir, target, Duration::ZERO);
	});
	let mut note = Vec::new();
	let waited = wait_within(store.store_path(), &mut note, Duration::from_secs(3));
	poster.join().expect("poster");
	assert_eq!(waited, Waited::Loaded);
	assert!(note.is_empty(), "a loaded change needs no note");
}

#[test]
fn missing_status_reads_as_no_server() {
	let (_dir, store) = fixture();
	let mut note = Vec::new();
	let waited = wait_within(store.store_path(), &mut note, Duration::from_secs(3));
	assert_eq!(waited, Waited::NoServer);
	assert!(note.is_empty(), "no server, nothing to note");
}
