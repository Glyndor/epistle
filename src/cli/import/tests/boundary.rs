//! The boundary of the limit: an entry that fits it is imported whole, and
//! one byte more is refused.

use super::*;
use std::io::Cursor;
use std::process::ExitCode;

/// The limit the tests import with.
const LIMIT: usize = 4096;

#[test]
fn an_entry_exactly_at_the_limit_is_imported_whole() {
	let dir = account_dir();
	let code = run(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
		Cursor::new(entry_of(LIMIT)),
		false,
		LIMIT,
		&mut std::io::sink(),
	);
	assert_eq!(code, ExitCode::SUCCESS, "an entry that fits is imported");
	let stored = stored(dir.path());
	assert_eq!(stored.len(), 1);
	assert_eq!(
		stored[0],
		message_of(LIMIT),
		"the message is imported whole"
	);
}

#[test]
fn an_entry_one_byte_over_the_limit_is_refused() {
	let dir = account_dir();
	let code = run(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
		Cursor::new(entry_of(LIMIT + 1)),
		false,
		LIMIT,
		&mut std::io::sink(),
	);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"an entry over the limit is an error"
	);
	assert!(
		stored(dir.path()).is_empty(),
		"nothing of the entry is imported"
	);
}

#[test]
fn a_maildir_file_exactly_at_the_limit_is_imported_whole() {
	let dir = account_dir();
	let maildir = dir.path().join("maildir");
	std::fs::create_dir_all(maildir.join("cur")).expect("mkdir");
	std::fs::write(maildir.join("cur").join("a"), "b".repeat(LIMIT)).expect("write");
	let code = run_maildir(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
		&maildir,
		false,
		LIMIT,
		&mut std::io::sink(),
	);
	assert_eq!(code, ExitCode::SUCCESS, "a file that fits is imported");
	let stored = stored(dir.path());
	assert_eq!(stored.len(), 1);
	assert_eq!(stored[0].len(), LIMIT, "the message is imported whole");
}

#[test]
fn a_maildir_file_one_byte_over_the_limit_is_refused() {
	let dir = account_dir();
	let maildir = dir.path().join("maildir");
	std::fs::create_dir_all(maildir.join("cur")).expect("mkdir");
	std::fs::write(maildir.join("cur").join("a"), "b".repeat(LIMIT + 1)).expect("write");
	let code = run_maildir(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
		&maildir,
		false,
		LIMIT,
		&mut std::io::sink(),
	);
	assert_eq!(code, ExitCode::FAILURE, "a file over the limit is an error");
	assert!(
		stored(dir.path()).is_empty(),
		"nothing of the file is imported"
	);
}
