//! The ledger file on disk: who can read it, and what a write never
//! touches.

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::run::block;
use super::support::rec;
use super::*;
use crate::dns::provider::RecordKind;
use crate::dns::reconcile::store;

/// A ledger with one record in it.
fn ledger() -> Ledger {
	let mut ledger = Ledger::new("example.org");
	ledger.remember(
		&rec("example.org", RecordKind::Txt, "v=spf1 mx -all"),
		None,
		1_800_000_000,
	);
	ledger
}

/// The mode of a file, without the bits that are not permissions.
fn mode_of(path: &std::path::Path) -> u32 {
	std::fs::metadata(path)
		.expect("the file is there")
		.permissions()
		.mode()
		& 0o777
}

#[test]
fn the_ledger_is_readable_by_its_owner_only() {
	let dir = tempfile::tempdir().expect("directory");
	store::store(dir.path(), &ledger()).expect("the ledger is written");
	let path = store::path(dir.path(), "example.org").expect("path");
	assert_eq!(
		mode_of(&path),
		0o600,
		"the ledger says what epistle published; nobody else reads it"
	);
}

#[test]
fn the_ledger_directory_is_private_too() {
	let dir = tempfile::tempdir().expect("directory");
	store::store(dir.path(), &ledger()).expect("the ledger is written");
	assert_eq!(mode_of(&store::dir(dir.path())), 0o700);
}

#[test]
fn a_symlink_where_the_ledger_goes_is_replaced_and_not_written_through() {
	// The write used to land on `<zone>.json.new` and then be renamed
	// over the ledger: a symlink at that name was written through, and
	// the JSON of the ledger ended up in whatever file it pointed at.
	// The write now goes through the safe helper of the rest of the
	// code, so a name already taken is replaced, never followed.
	let dir = tempfile::tempdir().expect("directory");
	let outside = tempfile::tempdir().expect("directory");
	let precious = outside.path().join("precious.txt");
	std::fs::write(&precious, "keep me").expect("the file is written");
	let path = store::path(dir.path(), "example.org").expect("path");
	std::fs::create_dir_all(path.parent().expect("the parent")).expect("the directory");
	std::os::unix::fs::symlink(&precious, &path).expect("the symlink is planted");
	store::store(dir.path(), &ledger()).expect("the ledger is written");
	assert_eq!(
		std::fs::read_to_string(&precious).expect("the file is read"),
		"keep me",
		"the file outside the data directory was not written through"
	);
	assert!(
		!path
			.symlink_metadata()
			.expect("the path is there")
			.file_type()
			.is_symlink(),
		"the symlink was replaced by the ledger"
	);
	assert!(
		store::load(dir.path(), "example.org")
			.expect("the ledger is read")
			.owns(&rec("example.org", RecordKind::Txt, "v=spf1 mx -all")),
		"the ledger is the one that was written"
	);
}

#[test]
fn a_symlink_at_the_old_staging_name_is_not_written_through() {
	// The staging name of the old write is not used any more: the
	// temporary file carries a unique name. A symlink left at the old
	// name is never touched.
	let dir = tempfile::tempdir().expect("directory");
	let outside = tempfile::tempdir().expect("directory");
	let precious = outside.path().join("precious.txt");
	std::fs::write(&precious, "keep me").expect("the file is written");
	let staging = store::path(dir.path(), "example.org")
		.expect("path")
		.with_extension("json.new");
	std::fs::create_dir_all(staging.parent().expect("the parent")).expect("the directory");
	std::os::unix::fs::symlink(&precious, &staging).expect("the symlink is planted");
	store::store(dir.path(), &ledger()).expect("the ledger is written");
	assert_eq!(
		std::fs::read_to_string(&precious).expect("the file is read"),
		"keep me",
		"the file outside the data directory was not written through"
	);
	assert!(
		staging
			.symlink_metadata()
			.expect("the path is there")
			.file_type()
			.is_symlink()
	);
}

#[test]
fn the_lock_file_is_readable_by_its_owner_only() {
	let dir = tempfile::tempdir().expect("directory");
	let _lock = store::lock(dir.path()).expect("lock").expect("free");
	assert_eq!(mode_of(&store::dir(dir.path()).join(".lock")), 0o600);
}

/// The lock of the ledger is the lock the rest of the code takes: a
/// publisher of another process and the reconcile loop cannot write at the
/// same time.
#[test]
fn the_ledger_lock_is_the_lock_the_rest_of_the_code_takes() {
	let dir = tempfile::tempdir().expect("directory");
	std::fs::create_dir_all(store::dir(dir.path())).expect("the directory");
	let path = store::dir(dir.path()).join(".lock");
	let held = crate::storage::lock::FileLock::try_acquire(&path)
		.expect("lock")
		.expect("free");
	assert!(
		store::lock(dir.path()).expect("lock").is_none(),
		"the lock of the rest of the code keeps the ledger out of reach"
	);
	drop(held);
	assert!(
		store::lock(dir.path()).expect("lock").is_some(),
		"the lock is free again"
	);
}

/// The wait for the lock does not stop the runtime: the caller waits
/// between two tries, so the server keeps answering while a publish holds
/// the ledger.
#[test]
fn waiting_for_the_lock_does_not_stop_the_runtime() {
	let dir = tempfile::tempdir().expect("directory");
	let _held = store::lock(dir.path()).expect("lock").expect("free");
	let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let flag = std::sync::Arc::clone(&ran);
	let data_dir = dir.path().to_path_buf();
	block(async move {
		tokio::spawn(async move {
			tokio::time::sleep(Duration::from_millis(50)).await;
			flag.store(true, std::sync::atomic::Ordering::SeqCst);
		});
		let taken = store::lock_wait(&data_dir, Duration::from_millis(200))
			.await
			.expect("lock");
		assert!(taken.is_none(), "the lock is held by somebody else");
	});
	assert!(
		ran.load(std::sync::atomic::Ordering::SeqCst),
		"the runtime kept running while the lock was waited for"
	);
}

/// A ledger that belongs to another zone is refused: the ledger of a zone
/// says what epistle published there, and the ledger of another zone would
/// turn every record in it foreign.
#[test]
fn a_ledger_for_another_zone_is_refused() {
	let dir = tempfile::tempdir().expect("directory");
	let path = store::path(dir.path(), "example.org").expect("path");
	std::fs::create_dir_all(path.parent().expect("the parent")).expect("the directory");
	let mut other = Ledger::new("other.net");
	other.remember(
		&rec("other.net", RecordKind::Txt, "v=spf1 mx -all"),
		None,
		1_800_000_000,
	);
	std::fs::write(&path, serde_json::to_string(&other).expect("json"))
		.expect("the file is written");
	let error = store::load(dir.path(), "example.org").expect_err("the ledger is for another zone");
	assert!(error.contains("other.net"), "{error}");
	assert!(error.contains("example.org"), "{error}");
}

/// The files of the directory that are not ledgers are not zones: the
/// staging file of a write and the lock file are not a zone epistle
/// published in.
#[test]
fn the_staging_and_the_lock_file_are_not_zones() {
	let dir = tempfile::tempdir().expect("directory");
	store::store(dir.path(), &ledger()).expect("the ledger is written");
	let staging = store::path(dir.path(), "example.org")
		.expect("path")
		.with_extension("json.new");
	std::fs::write(&staging, "{}").expect("the staging file is written");
	std::fs::write(store::dir(dir.path()).join(".lock"), "").expect("the lock file is written");
	assert_eq!(
		store::zones(dir.path()).expect("zones"),
		vec!["example.org".to_string()],
		"only a ledger is a zone"
	);
}

#[test]
fn a_ledger_that_cannot_be_read_stops_the_caller() {
	let dir = tempfile::tempdir().expect("directory");
	let path = store::path(dir.path(), "example.org").expect("path");
	std::fs::create_dir_all(path.parent().expect("the parent")).expect("the directory");
	std::fs::write(&path, "{not json").expect("the file is written");
	let error = store::load(dir.path(), "example.org").expect_err("the ledger is broken");
	assert!(error.contains("not readable"), "{error}");
}
