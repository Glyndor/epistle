use super::*;
use std::os::unix::fs::symlink;

#[test]
fn the_index_is_not_written_through_a_link_out_of_the_root() {
	let guard = tempfile::tempdir().expect("tempdir");
	let root = guard.path().join("data");
	let outside = guard.path().join("outside");
	std::fs::create_dir_all(&root).expect("mkdir root");
	std::fs::create_dir(&outside).expect("mkdir outside");
	let mailbox = root.join("box");
	symlink(&outside, &mailbox).expect("symlink");

	let error = write(&root, &mailbox, (1, 0, 0), &[]).expect_err("write");

	assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(std::fs::read_dir(&outside).expect("read_dir").count(), 0);
}
