//! An expunge never removes a file through a mailbox directory that was
//! replaced by a link out of the data directory.

use super::*;
use crate::storage::MessageCrypto;
use std::os::unix::fs::symlink;

#[test]
fn expunge_does_not_remove_files_through_a_link_out_of_the_data_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = tempfile::tempdir().expect("outside");
	let new_dir = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&new_dir).expect("mkdir");
	let id = Uuid::now_v7();
	std::fs::write(new_dir.join(format!("{id}.eml")), b"a\r\n").expect("write");
	let mut snapshot =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("store");
	// The mailbox directory is swapped for a link to a copy outside.
	std::fs::copy(
		new_dir.join(format!("{id}.eml")),
		outside.path().join(format!("{id}.eml")),
	)
	.expect("copy");
	std::fs::remove_dir_all(&new_dir).expect("remove");
	symlink(outside.path(), &new_dir).expect("symlink");

	let _ = snapshot.expunge();

	assert!(
		outside.path().join(format!("{id}.eml")).exists(),
		"the file behind the link was removed"
	);
}
