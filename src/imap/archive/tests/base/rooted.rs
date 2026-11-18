//! An archive directory or a mailbox replaced by a link out of the data
//! directory is never written through, and its messages are never moved.

use super::*;
use std::os::unix::fs::symlink;

/// The account directory is swapped for a link after the account root was
/// built, so `archive_dir` accepts the `.archive` name and the refusal has to
/// come from `create_dir_all`.
#[test]
fn an_account_swapped_for_a_link_receives_no_archive_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = tempfile::tempdir().expect("outside");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");
	let account = root(dir.path(), "alice");
	let real = account.as_path().to_path_buf();
	let moved = dir.path().join("alice-moved");
	std::fs::rename(&real, &moved).expect("move");
	symlink(outside.path(), &real).expect("symlink");
	let inbox = moved.join("new");

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
