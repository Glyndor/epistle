//! The header of a stored file is only peeked at when the file lies under the
//! trusted data directory.

use super::*;
use std::os::unix::fs::symlink;

#[test]
fn a_file_behind_a_link_out_of_the_root_is_not_opened_for_its_header() {
	let guard = tempfile::tempdir().expect("tempdir");
	let root = guard.path().join("data");
	let outside = guard.path().join("outside");
	std::fs::create_dir_all(&root).expect("mkdir root");
	std::fs::create_dir(&outside).expect("mkdir outside");
	let crypto = MessageCrypto::for_test(&[7u8; KEY_LEN]);
	let stored = crypto
		.encode(b"Subject: sized\r\n\r\nbody\r\n")
		.expect("encode");
	std::fs::write(outside.join("msg.eml"), &stored).expect("write");
	symlink(&outside, root.join("box")).expect("symlink");
	let through = root.join("box").join("msg.eml");

	// Opened, the envelope overhead would be taken off; refused, the stored
	// length is what is reported.
	let len = crypto.stored_plaintext_len(&root, &through, stored.len() as u64);
	assert_eq!(len, stored.len() as u64);

	let inside = outside.join("msg.eml");
	let seen = crypto.stored_plaintext_len(&outside, &inside, stored.len() as u64);
	assert!(
		seen < stored.len() as u64,
		"a file under its root is peeked"
	);
}
