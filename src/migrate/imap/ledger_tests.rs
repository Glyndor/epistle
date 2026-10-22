//! The ledger of confirmed messages, read and appended directly.

use super::*;
use crate::migrate::imap::state::StateDir;

/// A state directory and the ledger of `INBOX` under `uid_validity`.
fn at(dir: &std::path::Path, uid_validity: u32, writable: bool) -> Ledger {
	try_at(dir, uid_validity, writable).expect("ledger")
}

/// The same ledger, for the cases that expect the open to be refused.
fn try_at(dir: &std::path::Path, uid_validity: u32, writable: bool) -> std::io::Result<Ledger> {
	StateDir::open(dir, "alice", "alice@old.example")?.ledger(b"INBOX", uid_validity, writable)
}

fn fingerprint(seed: u8) -> Fingerprint {
	[seed; 32]
}

/// Where the ledger of `INBOX` lives in `dir`.
fn path_of(dir: &std::path::Path) -> std::path::PathBuf {
	StateDir::open(dir, "alice", "alice@old.example")
		.expect("state")
		.ledger_path(b"INBOX")
		.expect("path")
}

/// One record as it lies on disk.
fn record_of(uid: u32) -> Vec<u8> {
	let mut bytes = Vec::new();
	bytes.extend_from_slice(&uid.to_le_bytes());
	bytes.extend_from_slice(&fingerprint(uid as u8));
	bytes.extend_from_slice(&checksum(uid, &fingerprint(uid as u8)).to_le_bytes());
	bytes
}

#[test]
fn records_are_read_back_in_order_and_unknown_uids_are_not_confirmed() {
	let dir = tempfile::tempdir().expect("dir");
	let mut ledger = at(dir.path(), 7, true);
	assert_eq!((ledger.count(), ledger.last_uid()), (0, 0));
	ledger
		.confirm(&[(3, fingerprint(3)), (9, fingerprint(9))])
		.expect("confirm");
	ledger.confirm(&[(30, fingerprint(30))]).expect("confirm");
	assert_eq!((ledger.count(), ledger.last_uid()), (3, 30));
	for (uid, seed) in [(3, 3), (9, 9), (30, 30)] {
		assert_eq!(
			ledger.fingerprint(uid).expect("fingerprint"),
			Some(fingerprint(seed)),
			"uid {uid}"
		);
	}
	for uid in [1, 4, 8, 10, 29, 31, u32::MAX] {
		assert_eq!(
			ledger.fingerprint(uid).expect("fingerprint"),
			None,
			"uid {uid}"
		);
	}
	// Asking again out of order finds the same records.
	assert_eq!(
		ledger.fingerprint(3).expect("fingerprint"),
		Some(fingerprint(3))
	);
	assert_eq!(
		ledger.fingerprint(30).expect("fingerprint"),
		Some(fingerprint(30))
	);
	assert_eq!(ledger.fingerprint(29).expect("fingerprint"), None);
}

#[test]
fn a_rerun_reads_what_the_last_one_confirmed() {
	let dir = tempfile::tempdir().expect("dir");
	{
		let mut ledger = at(dir.path(), 7, true);
		ledger
			.confirm(&[(1, fingerprint(1)), (2, fingerprint(2))])
			.expect("confirm");
	}
	let mut ledger = at(dir.path(), 7, false);
	assert_eq!((ledger.count(), ledger.last_uid()), (2, 2));
	assert_eq!(
		ledger.fingerprint(2).expect("fingerprint"),
		Some(fingerprint(2))
	);
}

#[test]
fn records_below_the_last_one_are_left_out_and_a_batch_that_does_not_rise_is_refused() {
	let dir = tempfile::tempdir().expect("dir");
	let path = path_of(dir.path());
	let mut ledger = at(dir.path(), 7, true);
	ledger.confirm(&[(5, fingerprint(5))]).expect("confirm");

	// What a folder that has to be replayed from the start confirms: messages
	// below what an earlier batch already reached. They are left out, so that
	// folder can finish.
	ledger.confirm(&[(3, fingerprint(3))]).expect("confirm");
	ledger
		.confirm(&[(5, fingerprint(5)), (6, fingerprint(6))])
		.expect("confirm");
	assert_eq!(
		(ledger.count(), ledger.last_uid()),
		(2, 6),
		"only the records above the UID the file reaches are appended"
	);
	for (uid, confirmed) in [
		(3, None),
		(5, Some(fingerprint(5))),
		(6, Some(fingerprint(6))),
	] {
		assert_eq!(
			ledger.fingerprint(uid).expect("fingerprint"),
			confirmed,
			"uid {uid}"
		);
	}

	// A batch that does not rise cannot be told apart from the one that
	// follows it, so it is refused by name, before anything is written.
	for records in [
		vec![(9, fingerprint(9)), (8, fingerprint(8))],
		vec![(7, fingerprint(7)), (7, fingerprint(7))],
	] {
		let message = ledger
			.confirm(&records)
			.expect_err("a batch that does not rise")
			.to_string();
		assert!(
			message.contains("UID order")
				&& message.contains(&path.display().to_string())
				&& message.contains("delete that file"),
			"the refusal names the file and how to start over: {message}"
		);
	}
	assert_eq!(
		(ledger.count(), ledger.last_uid()),
		(2, 6),
		"a refused batch writes nothing"
	);
}

#[test]
fn a_file_that_no_longer_holds_what_was_read_is_refused_before_anything_is_written() {
	let dir = tempfile::tempdir().expect("dir");
	let path = path_of(dir.path());
	let mut ledger = at(dir.path(), 7, true);
	ledger.confirm(&[(5, fingerprint(5))]).expect("confirm");

	// Another run of the same account appends a record of its own while this
	// handle is open. The offset this run computed no longer names the end of
	// the file, so the record of the other run would be written over.
	let other = std::fs::OpenOptions::new()
		.write(true)
		.open(&path)
		.expect("open");
	other
		.write_all_at(&record_of(9), HEADER + RECORD)
		.expect("append");
	let message = ledger
		.confirm(&[(10, fingerprint(10))])
		.expect_err("another writer")
		.to_string();
	assert!(
		message.contains("another run is writing")
			&& message.contains(&path.display().to_string())
			&& message.contains("one migration of this account at a time"),
		"the refusal says what to do: {message}"
	);
	assert_eq!(
		(ledger.count(), ledger.last_uid()),
		(1, 5),
		"nothing is written over the other run's record"
	);

	// The same when the file lost records instead of gaining them.
	other.set_len(HEADER).expect("truncate");
	let message = ledger
		.confirm(&[(10, fingerprint(10))])
		.expect_err("a file that lost records")
		.to_string();
	assert!(message.contains("another run is writing"), "{message}");
	assert_eq!(ledger.count(), 1);
}

#[test]
fn a_ledger_whose_records_repeat_or_go_backwards_is_refused_when_it_is_read() {
	let dir = tempfile::tempdir().expect("dir");
	let path = path_of(dir.path());
	at(dir.path(), 7, true)
		.confirm(&[(4, fingerprint(4))])
		.expect("confirm");

	// A ledger written by this code and then rewritten by hand: the same
	// marker, the same UIDVALIDITY, every checksum in order, and records that
	// do not rise. Answering from it would silently skip or invent messages.
	for uids in [vec![5u32, 5], vec![10, 5], vec![4, 9, 4], vec![9, 8, 9, 10]] {
		let mut body = header(7);
		for uid in uids {
			body.extend_from_slice(&record_of(uid));
		}
		std::fs::write(&path, body).expect("write");
		let message = try_at(dir.path(), 7, true)
			.expect_err("records that do not rise")
			.to_string();
		assert!(
			message.contains("UID order") && message.contains(&path.display().to_string()),
			"a ledger that does not rise is named: {message}"
		);
	}

	// The same records in order are read, and so is a record in the middle of
	// them.
	let mut body = header(7);
	for uid in [4, 9, 40] {
		body.extend_from_slice(&record_of(uid));
	}
	std::fs::write(&path, body).expect("write");
	let mut ledger = at(dir.path(), 7, false);
	assert_eq!(
		(ledger.count(), ledger.last_uid()),
		(3, 40),
		"records that rise are read"
	);
	assert_eq!(
		ledger.fingerprint(9).expect("fingerprint"),
		Some(fingerprint(9))
	);
}

#[test]
fn a_changed_uidvalidity_discards_the_ledger_and_an_absent_one_confirms_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let mut ledger = at(dir.path(), 7, true);
	ledger
		.confirm(&[(1, fingerprint(1)), (2, fingerprint(2))])
		.expect("confirm");

	let discarded = at(dir.path(), 9, true);
	assert_eq!(
		(discarded.uid_validity(), discarded.count()),
		(9, 0),
		"nothing of the old UIDVALIDITY is left"
	);
	assert!(
		std::fs::metadata(
			StateDir::open(dir.path(), "alice", "alice@old.example")
				.expect("state")
				.ledger_path(b"INBOX")
				.expect("path")
		)
		.expect("metadata")
		.len() <= HEADER
	);

	// A source without UIDVALIDITY has no ledger at all, and writes nothing.
	let fresh = tempfile::tempdir().expect("dir");
	let mut none = at(fresh.path(), 0, true);
	assert_eq!(none.fingerprint(1).expect("fingerprint"), None);
	// Confirming one of its messages changes nothing and is not a refusal: its
	// UIDs name nothing that could be looked up later.
	none.confirm(&[(1, fingerprint(1))]).expect("confirm");
	none.confirm(&[(2, fingerprint(2))]).expect("confirm");
	assert_eq!(
		(none.count(), none.last_uid()),
		(0, 0),
		"a source without UIDVALIDITY confirms nothing"
	);
	assert!(
		!fresh.path().join("migrate/alice/x.ledger").exists()
			&& std::fs::read_dir(fresh.path())
				.expect("list")
				.next()
				.is_none(),
		"a source without UIDVALIDITY writes nothing"
	);

	// A ledger opened to be read adds nothing either.
	let mut sealed = at(dir.path(), 9, false);
	sealed.confirm(&[(99, fingerprint(99))]).expect("confirm");
	assert_eq!(
		sealed.count(),
		0,
		"a ledger that can only be read is not appended to"
	);
}

#[test]
fn a_torn_tail_record_is_dropped_and_the_rest_still_answers() {
	let dir = tempfile::tempdir().expect("dir");
	let mut ledger = at(dir.path(), 7, true);
	ledger
		.confirm(&[(1, fingerprint(1)), (2, fingerprint(2))])
		.expect("confirm");
	ledger.confirm(&[(3, fingerprint(3))]).expect("confirm");
	let path = StateDir::open(dir.path(), "alice", "alice@old.example")
		.expect("state")
		.ledger_path(b"INBOX")
		.expect("path");
	let file = std::fs::OpenOptions::new()
		.write(true)
		.open(&path)
		.expect("open");
	// An append the power cut left seven octets short.
	file.set_len(HEADER + 3 * RECORD - 7).expect("truncate");
	drop(ledger);

	let mut reopened = at(dir.path(), 7, true);
	assert_eq!(
		(reopened.count(), reopened.last_uid()),
		(2, 2),
		"the unfinished record is dropped and the file is cut back to it"
	);
	assert_eq!(
		std::fs::metadata(&path).expect("metadata").len(),
		HEADER + 2 * RECORD,
		"the cut record is gone from the file"
	);
	assert_eq!(
		reopened.fingerprint(2).expect("fingerprint"),
		Some(fingerprint(2))
	);
	assert_eq!(reopened.fingerprint(3).expect("fingerprint"), None);
}

#[test]
fn an_altered_record_and_an_altered_header_are_refused_with_advice() {
	let dir = tempfile::tempdir().expect("dir");
	let mut ledger = at(dir.path(), 7, true);
	ledger
		.confirm(&[
			(1, fingerprint(1)),
			(2, fingerprint(2)),
			(3, fingerprint(3)),
		])
		.expect("confirm");
	let states = StateDir::open(dir.path(), "alice", "alice@old.example").expect("state");
	let path = states.ledger_path(b"INBOX").expect("path");

	// A record whose fingerprint does not match its checksum.
	let mut body = std::fs::read(&path).expect("read");
	body[HEADER as usize + RECORD as usize + 4] ^= 0xff;
	std::fs::write(&path, &body).expect("write");
	let message = try_at(dir.path(), 7, true)
		.and_then(|mut ledger| ledger.fingerprint(2))
		.expect_err("altered record")
		.to_string();
	assert!(
		message.contains("checksum") && message.contains(&path.display().to_string()),
		"an altered record is named: {message}"
	);

	// A file that is not a ledger at all.
	std::fs::write(&path, b"{} this is not a ledger").expect("write");
	let message = try_at(dir.path(), 7, true)
		.expect_err("not a ledger")
		.to_string();
	assert!(
		message.contains("marker") && message.contains("delete that file"),
		"a file that is not a ledger says how to start over: {message}"
	);

	// A header cut in half.
	std::fs::write(&path, b"EPSTLG1\0").expect("write");
	assert!(
		try_at(dir.path(), 7, true)
			.expect_err("short header")
			.to_string()
			.contains("header")
	);
}

#[test]
fn a_ledger_of_seventy_thousand_messages_answers_within_a_fixed_workspace() {
	const MESSAGES: u32 = 70_000;
	let dir = tempfile::tempdir().expect("dir");
	let mut ledger = at(dir.path(), 7, true);
	let mut confirmed = 0;
	for base in (1..=MESSAGES).step_by(10_000) {
		let batch: Vec<_> = (base..base + 10_000)
			.map(|uid| (uid, fingerprint((uid % 251) as u8)))
			.collect();
		ledger.confirm(&batch).expect("confirm");
		confirmed += batch.len() as u64;
	}
	assert_eq!(ledger.count(), confirmed);
	let path = StateDir::open(dir.path(), "alice", "alice@old.example")
		.expect("state")
		.ledger_path(b"INBOX")
		.expect("path");
	assert_eq!(
		std::fs::metadata(&path).expect("metadata").len(),
		HEADER + u64::from(MESSAGES) * RECORD,
		"40 octets per confirmed message"
	);

	// The workspace one folder is charged does not grow with the number of
	// records it holds: the file is read where it lies. The bound is written
	// here rather than taken from the module, so raising what a folder costs
	// cannot quietly raise what the test accepts.
	const FOLDER_WORKSPACE: usize = 64 * 1024;
	let mut budget = Budget::default();
	budget.mailbox_limit = FOLDER_WORKSPACE;
	charge(&mut budget).expect("one folder's ledger fits a fixed workspace");
	for uid in 1..=MESSAGES {
		assert_eq!(
			ledger.fingerprint(uid).expect("fingerprint"),
			Some(fingerprint((uid % 251) as u8)),
			"uid {uid}"
		);
	}
	// A second folder does not fit in the same workspace.
	assert!(matches!(
		charge(&mut budget),
		Err(ClientError::Metadata {
			scope: "mailbox",
			..
		})
	));
}

#[cfg(unix)]
#[test]
fn the_ledger_is_private_and_refuses_links() {
	use std::os::unix::fs::{PermissionsExt, symlink};
	let dir = tempfile::tempdir().expect("dir");
	at(dir.path(), 7, true)
		.confirm(&[(1, fingerprint(1))])
		.expect("confirm");
	let path = StateDir::open(dir.path(), "alice", "alice@old.example")
		.expect("state")
		.ledger_path(b"INBOX")
		.expect("path");
	assert_eq!(
		std::fs::metadata(&path)
			.expect("metadata")
			.permissions()
			.mode() & 0o777,
		0o600
	);
	let outside = tempfile::tempdir().expect("outside");
	let victim = outside.path().join("victim");
	std::fs::write(&victim, std::fs::read(&path).expect("read")).expect("write");
	std::fs::remove_file(&path).expect("remove");
	symlink(&victim, &path).expect("link");
	assert!(
		try_at(dir.path(), 7, true).is_err(),
		"a linked ledger is not followed"
	);
}

#[test]
fn a_thousand_empty_folders_never_add_up_to_the_total() {
	// Each folder holds its workspace only while it is open, so the number of
	// folders cannot exhaust the total the whole run is allowed.
	let mut budget = Budget::default();
	for _ in 0..4000 {
		budget.next_mailbox();
		charge(&mut budget).expect("a folder's workspace is not part of the total");
	}
}
