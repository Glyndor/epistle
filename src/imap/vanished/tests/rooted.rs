use super::*;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;

/// A data directory whose mailbox directory is a link to a directory outside.
fn linked() -> (
	tempfile::TempDir,
	std::path::PathBuf,
	std::path::PathBuf,
	std::path::PathBuf,
) {
	let guard = tempfile::tempdir().expect("tempdir");
	let root = guard.path().join("data");
	let outside = guard.path().join("outside");
	std::fs::create_dir_all(&root).expect("mkdir root");
	std::fs::create_dir(&outside).expect("mkdir outside");
	let mailbox = root.join("box");
	symlink(&outside, &mailbox).expect("symlink");
	(guard, root, mailbox, outside)
}

#[test]
fn an_expunge_is_not_logged_through_a_link_out_of_the_root() {
	let (_guard, root, mailbox, outside) = linked();
	let error = record(&root, &mailbox, &[1, 2], 5).expect_err("record");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	assert_eq!(std::fs::read_dir(&outside).expect("read_dir").count(), 0);
}

#[test]
fn the_log_is_not_read_through_a_link_out_of_the_root() {
	let (_guard, root, mailbox, outside) = linked();
	std::fs::write(outside.join(".vanished"), "7 9\n").expect("log");
	assert!(since(&root, &mailbox, 0).is_empty());
	let error = tail(&root, &mailbox.join(".vanished"), MAX_LOG_OCTETS).expect_err("tail");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn trimming_rewrites_nothing_through_a_link_out_of_the_root() {
	let (_guard, root, mailbox, outside) = linked();
	std::fs::write(outside.join(".vanished"), "7 9\n").expect("log");
	let error = trim(&root, &mailbox.join(".vanished")).expect_err("trim");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	assert_eq!(
		std::fs::read_to_string(outside.join(".vanished")).expect("read"),
		"7 9\n"
	);
	assert_eq!(std::fs::read_dir(&outside).expect("read_dir").count(), 1);
}
