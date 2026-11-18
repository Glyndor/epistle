//! A mailbox directory replaced by a link out of the data directory is never
//! written through: the counter, the stamps and the lock stay inside.

use super::super::{lock, next_counter, write_message};
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use uuid::Uuid;

/// A data directory whose mailbox directory is a link to a directory outside.
fn linked() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
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
fn the_counter_a_stamp_and_the_lock_are_refused_through_a_link_out_of_the_root() {
	let (_guard, root, mailbox, outside) = linked();
	let error = next_counter(&root, &mailbox).expect_err("counter");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	let error = write_message(&root, &mailbox, Uuid::now_v7(), 5).expect_err("stamp");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	let error = lock(&root, &mailbox).expect_err("lock");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	assert_eq!(std::fs::read_dir(&outside).expect("read_dir").count(), 0);
}
