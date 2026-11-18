//! A mailbox directory replaced by a link out of the data directory never
//! gets a UIDVALIDITY recorded through it.

use super::read_or_init;
use crate::util::path_component::AccountName;
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
