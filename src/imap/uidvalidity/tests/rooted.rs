//! A mailbox directory replaced by a link out of the data directory never
//! gets a UIDVALIDITY recorded through it.

use super::read_or_init;
use crate::util::path_component::{AccountName, StateFile};
use std::os::unix::fs::symlink;

#[test]
fn a_mailbox_linked_out_of_the_data_directory_records_nothing_outside() {
	let guard = tempfile::tempdir().unwrap();
	let data = guard.path().join("data");
	let outside = guard.path().join("outside");
	std::fs::create_dir_all(data.join("accounts/alice/folders")).unwrap();
	std::fs::create_dir_all(outside.join("new")).unwrap();
	let root = AccountName::new("alice").unwrap().root(&data).unwrap();
	let mailbox = root.as_path().join("folders").join("box");
	symlink(&outside, &mailbox).unwrap();
	let dir = mailbox.join("new");

	let value = read_or_init(&dir, &root);

	assert!(value > 0);
	assert_eq!(std::fs::read_dir(outside.join("new")).unwrap().count(), 0);
	assert!(!root.as_path().join(".uidvalidity_last").exists());
}

/// A real account and mailbox, so only the file under test is wrong.
fn account(
	data: &std::path::Path,
) -> (crate::util::path_component::AccountRoot, std::path::PathBuf) {
	std::fs::create_dir_all(data.join("accounts/alice")).unwrap();
	let root = AccountName::new("alice").unwrap().root(data).unwrap();
	let dir = root.as_path().join("folders").join("box").join("new");
	std::fs::create_dir_all(&dir).unwrap();
	(root, dir)
}

#[test]
fn a_lock_file_linked_out_of_the_data_directory_is_refused() {
	let guard = tempfile::tempdir().unwrap();
	let data = guard.path().join("data");
	let outside = guard.path().join("outside");
	std::fs::create_dir_all(&data).unwrap();
	std::fs::write(&outside, "kept").unwrap();
	let (root, dir) = account(&data);
	symlink(&outside, root.as_path().join(".uidvalidity_lock")).unwrap();

	let error = super::lock(&root).expect_err("lock");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

	// Opening the mailbox goes on without the lock and records nothing.
	assert!(read_or_init(&dir, &root) > 0);
	assert!(!root.as_path().join(".uidvalidity_last").exists());
	assert!(!dir.join(".uidvalidity").exists());
	assert_eq!(std::fs::read_to_string(&outside).unwrap(), "kept");
}

#[test]
fn a_counter_written_into_a_directory_linked_out_is_refused() {
	let guard = tempfile::tempdir().unwrap();
	let data = guard.path().join("data");
	let outside = guard.path().join("outside");
	std::fs::create_dir_all(&data).unwrap();
	std::fs::create_dir(&outside).unwrap();
	let (root, _dir) = account(&data);
	let linked = root.as_path().join("linked");
	symlink(&outside, &linked).unwrap();

	let error =
		super::write(root.data_dir(), &linked, StateFile::UidValidity, 7).expect_err("write");

	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}
