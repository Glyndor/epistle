//! An archive directory or a mailbox replaced by a link out of the data
//! directory is never written through, and its messages are never moved.

use super::*;
use std::os::unix::fs::symlink;

#[test]
fn an_archive_linked_out_of_the_data_directory_receives_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = tempfile::tempdir().expect("outside");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");
	let account = root(dir.path(), "alice");
	symlink(outside.path(), account.as_path().join(".archive")).expect("symlink");
	let inbox = account.as_path().join("new");

	let result = archive::archive_message(&account, &inbox, "INBOX", id, 1_000);

	assert_eq!(
		result.expect_err("refused").kind(),
		std::io::ErrorKind::InvalidInput
	);
	assert_eq!(std::fs::read_dir(outside.path()).expect("read").count(), 0);
	assert!(
		inbox.join(format!("{id}.eml")).exists(),
		"the message stays"
	);
}

#[test]
fn a_mailbox_linked_out_of_the_data_directory_is_not_moved_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = tempfile::tempdir().expect("outside");
	let account = root(dir.path(), "alice");
	std::fs::create_dir_all(account.as_path()).expect("mkdir");
	let id = Uuid::now_v7();
	std::fs::write(outside.path().join(format!("{id}.eml")), b"x").expect("write");
	let mailbox = account.as_path().join("linked");
	symlink(outside.path(), &mailbox).expect("symlink");

	let result = archive::archive_message(&account, &mailbox, "Linked", id, 1_000);

	assert_eq!(
		result.expect_err("refused").kind(),
		std::io::ErrorKind::InvalidInput
	);
	assert!(outside.path().join(format!("{id}.eml")).exists());
	assert!(
		!account
			.as_path()
			.join(".archive")
			.join(format!("{id}.eml"))
			.exists()
	);
}
