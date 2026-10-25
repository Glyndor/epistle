//! What a lookup and an open cost on a ledger with many records.

use super::*;
use crate::migrate::imap::state::StateDir;

fn open(dir: &std::path::Path, writable: bool) -> io::Result<Ledger> {
	StateDir::open(dir, "alice", "alice@old.example")?.ledger(b"INBOX", 7, writable)
}

fn seed(uid: u32) -> Fingerprint {
	[uid as u8; 32]
}

fn reads() -> u64 {
	READS.with(std::cell::Cell::get)
}

#[test]
fn a_replay_in_uid_order_reads_the_file_in_windows_not_per_message() {
	let dir = tempfile::tempdir().expect("dir");
	let records: Vec<_> = (1..=4000u32).map(|uid| (uid, seed(uid))).collect();
	open(dir.path(), true)
		.expect("ledger")
		.confirm(&records)
		.expect("confirm");
	let mut ledger = open(dir.path(), false).expect("reopened");
	let before = reads();
	for uid in 1..=4000u32 {
		assert_eq!(
			ledger.fingerprint(uid).expect("fingerprint"),
			Some(seed(uid)),
			"uid {uid}"
		);
	}
	let used = reads() - before;
	// One search to place the cursor, then one read per window of records.
	assert!(
		used < 40,
		"4000 sequential lookups took {used} positional reads"
	);
}

#[test]
fn a_far_jump_still_finds_the_record_and_the_gaps_between_them() {
	let dir = tempfile::tempdir().expect("dir");
	let records: Vec<_> = (1..=3000u32).map(|n| (n * 2, seed(n))).collect();
	open(dir.path(), true)
		.expect("ledger")
		.confirm(&records)
		.expect("confirm");
	let mut ledger = open(dir.path(), false).expect("reopened");
	for uid in [2, 3, 4, 500, 501, 502, 4000, 5999, 6000, 6001, 7000] {
		let expected = (uid % 2 == 0 && uid <= 6000).then(|| seed(uid / 2));
		assert_eq!(
			ledger.fingerprint(uid).expect("fingerprint"),
			expected,
			"uid {uid}"
		);
	}
}

#[test]
fn a_ledger_over_the_size_bound_is_refused_before_it_is_read() {
	let dir = tempfile::tempdir().expect("dir");
	let mut ledger = open(dir.path(), true).expect("ledger");
	ledger.confirm(&[(1, seed(1))]).expect("confirm");
	drop(ledger);
	let path = StateDir::open(dir.path(), "alice", "alice@old.example")
		.expect("state")
		.ledger_path(b"INBOX")
		.expect("path");
	let file = std::fs::OpenOptions::new()
		.write(true)
		.open(&path)
		.expect("open");
	file.set_len(MAX_LEDGER_BYTES + RECORD).expect("grow");
	let message = open(dir.path(), false)
		.expect_err("a ledger past the bound")
		.to_string();
	assert!(message.contains("holds more than"), "{message}");
}

#[test]
fn a_uid_above_the_last_confirmed_one_is_answered_without_reading() {
	let dir = tempfile::tempdir().expect("dir");
	let records: Vec<_> = (1..=4000u32).map(|uid| (uid, seed(uid))).collect();
	open(dir.path(), true)
		.expect("ledger")
		.confirm(&records)
		.expect("confirm");
	let mut ledger = open(dir.path(), false).expect("reopened");
	let before = reads();
	for uid in 4001..5000 {
		assert_eq!(ledger.fingerprint(uid).expect("fingerprint"), None);
	}
	assert_eq!(reads(), before, "a resume above the ledger never reads it");
	assert_eq!(ledger.fingerprint(4000).expect("last"), Some(seed(4000)));
}
