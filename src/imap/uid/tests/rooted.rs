//! A mailbox directory replaced by a link out of the data directory is never
//! written through: the counter, the sidecars and the lock stay inside.

use super::super::{resolve_uids, write_counter, write_message};
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

fn untouched(outside: &std::path::Path) {
	let names: Vec<_> = std::fs::read_dir(outside).expect("read_dir").collect();
	assert!(names.is_empty(), "something was written outside the root");
}

#[test]
fn a_sidecar_and_the_counter_are_refused_through_a_link_out_of_the_root() {
	let (_guard, root, mailbox, outside) = linked();
	let error = write_message(&root, &mailbox, Uuid::now_v7(), 1).expect_err("sidecar");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	let error = write_counter(&root, &mailbox, 1).expect_err("counter");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	untouched(&outside);
}

#[test]
fn assigning_uids_through_a_link_out_of_the_root_writes_nothing_outside() {
	let (_guard, root, mailbox, outside) = linked();
	let ids = [Uuid::now_v7(), Uuid::now_v7()];
	let _ = resolve_uids(&root, &mailbox, &ids);
	untouched(&outside);
}
