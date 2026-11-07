//! The mbox import: an entry that goes past the limit is refused, named and
//! counted, and the entries around it are imported whole.

use super::*;
use std::io::Cursor;
use std::process::ExitCode;

/// The limit the tests import with: small enough that a test entry goes
/// past it, and small enough that the memory an import takes is visible.
const LIMIT: usize = 64 * 1024;

/// Import the mbox in `stream` into a fresh account.
fn import(stream: Vec<u8>, limit: usize) -> (ExitCode, tempfile::TempDir) {
	let dir = account_dir();
	let code = run(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
		Cursor::new(stream),
		false,
		limit,
		&mut std::io::sink(),
	);
	(code, dir)
}

/// An mbox with the given entries, in order.
fn mbox(entries: &[Vec<u8>]) -> Vec<u8> {
	entries.concat()
}

#[test]
fn a_giant_entry_between_two_normal_ones_is_refused_and_the_others_are_imported() {
	let stream = mbox(&[
		entry_of(1024),
		entry_of_lines(4 * 1024 * 1024),
		entry_of(2048),
	]);
	let (code, dir) = import(stream, LIMIT);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"an entry over the limit is an error"
	);
	let stored = stored(dir.path());
	assert_eq!(stored.len(), 2, "the two normal entries are imported");
	assert_eq!(stored[0], message_of(1024));
	assert_eq!(stored[1], message_of(2048));
}

#[test]
fn an_entry_with_a_line_over_the_limit_is_refused_and_the_next_entry_is_imported() {
	// One line longer than the limit cannot fit a message of the limit's
	// size: the rest of the line is read and dropped, and the entry
	// after it is imported.
	let mut giant = Vec::from(b"From MAILER-DAEMON@localhost\r\nSubject: x\r\n\r\n");
	giant.extend(std::iter::repeat_n(b'b', LIMIT + 1));
	giant.extend_from_slice(b"\r\n\r\n");
	let stream = mbox(&[giant, entry_of(1024)]);
	let (code, dir) = import(stream, LIMIT);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"an entry over the limit is an error"
	);
	let stored = stored(dir.path());
	assert_eq!(stored.len(), 1, "the entry after it is imported");
	assert_eq!(stored[0], message_of(1024));
}

#[test]
fn the_memory_an_import_takes_does_not_grow_with_the_entry_it_refuses() {
	let small = mbox(&[entry_of_lines(1024 * 1024)]);
	let large = mbox(&[entry_of_lines(8 * 1024 * 1024)]);
	let (_, peak_small) = crate::sieve::test_peak_bytes(|| import(small, LIMIT));
	let (_, peak_large) = crate::sieve::test_peak_bytes(|| import(large, LIMIT));
	assert!(
		peak_large < 1024 * 1024,
		"the import must not hold the entry it refuses: {peak_large} bytes"
	);
	assert!(
		peak_large < peak_small.saturating_mul(4).saturating_add(256 * 1024),
		"the memory must not follow the size of the entry: {peak_small} then {peak_large} bytes"
	);
}

#[test]
fn the_json_names_every_entry_the_import_refused() {
	let dir = account_dir();
	let mut out: Vec<u8> = Vec::new();
	let code = run(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
		Cursor::new(mbox(&[entry_of(1024), entry_of_lines(4 * 1024 * 1024)])),
		true,
		LIMIT,
		&mut out,
	);
	assert_eq!(code, ExitCode::FAILURE);
	let json: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(json["imported"], 1);
	assert_eq!(json["rejected"], 1);
	assert_eq!(json["rejected_entries"][0]["name"], "entry 2");
	assert_eq!(json["rejected_entries"][0]["limit"], LIMIT as u64);
}

#[test]
fn the_text_names_every_entry_the_import_refused() {
	let entry = Rejected {
		name: "entry 2".to_string(),
		limit: LIMIT,
	};
	assert_eq!(
		crate::cli::import::refusal(&entry),
		"entry 2 is over the message size limit (65536 bytes); it was not imported"
	);
}
