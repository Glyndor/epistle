//! The Maildir import: a message that goes past the limit is refused, named
//! by its path, and the rest of the folder is imported.

use super::*;
use std::process::ExitCode;

/// The limit the tests import with.
const LIMIT: usize = 4096;

#[test]
fn a_maildir_file_over_the_limit_is_refused_and_named() {
	let dir = account_dir();
	let maildir = dir.path().join("maildir");
	std::fs::create_dir_all(maildir.join("cur")).expect("mkdir");
	std::fs::write(
		maildir.join("cur").join("small"),
		"Subject: small\n\nbody\n",
	)
	.expect("write");
	std::fs::write(maildir.join("cur").join("big"), "b".repeat(LIMIT + 1)).expect("write");
	let mut out: Vec<u8> = Vec::new();
	let code = run_maildir(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
		&maildir,
		true,
		LIMIT,
		&mut out,
	);
	assert_eq!(code, ExitCode::FAILURE, "a file over the limit is an error");
	let stored = stored(dir.path());
	assert_eq!(stored.len(), 1, "the file that fits is imported");
	assert!(String::from_utf8_lossy(&stored[0]).contains("body"));
	let json: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(json["imported"], 1);
	assert_eq!(json["rejected"], 1);
	let name = json["rejected_entries"][0]["name"]
		.as_str()
		.expect("the refused file is named");
	assert!(name.ends_with("big"), "the refused file is named: {name}");
	assert_eq!(json["rejected_entries"][0]["limit"], LIMIT as u64);
}

#[test]
fn a_maildir_file_over_the_limit_is_not_read_whole() {
	// The file is much bigger than the limit: the import stops at the
	// limit and never holds the rest of it.
	let dir = account_dir();
	let maildir = dir.path().join("maildir");
	std::fs::create_dir_all(maildir.join("cur")).expect("mkdir");
	std::fs::write(maildir.join("cur").join("big"), "b".repeat(8 * 1024 * 1024)).expect("write");
	let (code, peak) = crate::sieve::test_peak_bytes(|| {
		run_maildir(
			dir.path(),
			"alice",
			&crate::storage::MessageCrypto::disabled(),
			&maildir,
			false,
			LIMIT,
			&mut std::io::sink(),
		)
	});
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		peak < 1024 * 1024,
		"the import must not hold the file it refuses: {peak} bytes"
	);
}
