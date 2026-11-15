//! COPY and MOVE take the quota decision the way APPEND does: under the
//! account's admission lock, with the same `[OVERQUOTA]` answer, and a copy
//! that stops half way leaves nothing in the destination.

use super::*;
use crate::test_support::fixtures;

const MESSAGE_BYTES: usize = 2_000;
const SESSIONS: usize = 8;
const ROUNDS: usize = 6;

fn message(n: usize) -> Vec<u8> {
	let mut text = format!("From: a@example.org\r\nTo: alice@example.org\r\nSubject: m{n}\r\n\r\n")
		.into_bytes();
	text.resize(MESSAGE_BYTES, b'x');
	text
}

fn session(dir: &std::path::Path, limit: u64) -> Session {
	let mut session =
		Session::new("mail.example.org", dir.to_path_buf(), directory()).with_quota_limit(limit);
	session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	session.command_line("a2 CREATE Archive");
	let selected = text(&session.command_line("a3 SELECT INBOX"));
	assert!(selected.contains("a3 OK"), "{selected}");
	session
}

fn archived(dir: &std::path::Path) -> usize {
	crate::imap::mailbox::Snapshot::open(
		dir,
		"alice",
		"Archive",
		&crate::storage::MessageCrypto::disabled(),
	)
	.map_or(0, |snapshot| snapshot.len())
}

fn usage(dir: &std::path::Path) -> u64 {
	crate::imap::mailbox::account_usage(dir, "alice", &crate::storage::MessageCrypto::disabled())
}

#[test]
fn copy_over_quota_is_refused_and_copies_nothing() {
	for command in ["COPY", "UID COPY"] {
		let dir = tempfile::tempdir().expect("tempdir");
		for n in 0..3 {
			deliver(dir.path(), &message(n));
		}
		// Three messages stored; room for one more, not for two.
		let limit = (MESSAGE_BYTES * 4 + MESSAGE_BYTES / 2) as u64;
		let mut session = session(dir.path(), limit);
		let refused = text(&session.command_line(&format!("b1 {command} 1:2 Archive")));
		assert!(refused.contains("b1 NO [OVERQUOTA]"), "{refused}");
		assert_eq!(archived(dir.path()), 0, "a refused COPY copies nothing");
		let copied = text(&session.command_line(&format!("b2 {command} 1 Archive")));
		assert!(copied.contains("b2 OK"), "{copied}");
		assert_eq!(archived(dir.path()), 1);
		let refused = text(&session.command_line(&format!("b3 {command} 1 Archive")));
		assert!(refused.contains("b3 NO [OVERQUOTA]"), "{refused}");
		assert_eq!(archived(dir.path()), 1);
		assert!(usage(dir.path()) <= limit);
	}
}

#[test]
fn move_at_the_quota_still_works() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), &message(0));
	// The account is exactly full: a MOVE does not grow it.
	let mut session = session(dir.path(), MESSAGE_BYTES as u64);
	let moved = text(&session.command_line("b1 MOVE 1 Archive"));
	assert!(moved.contains("b1 OK"), "{moved}");
	assert_eq!(archived(dir.path()), 1);
	assert_eq!(usage(dir.path()), MESSAGE_BYTES as u64);
}

#[test]
fn a_copy_that_stops_half_way_leaves_nothing_behind() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), &message(0));
	deliver(dir.path(), &message(1));
	let mut session = session(dir.path(), 0);
	// The second message disappears from disk after the session read the
	// mailbox: its copy fails after the first one was written.
	let mut files: Vec<_> = std::fs::read_dir(dir.path().join("accounts/alice/new"))
		.expect("read inbox")
		.map(|entry| entry.expect("entry").path())
		.filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
		.collect();
	files.sort();
	std::fs::remove_file(files.last().expect("a message")).expect("remove");
	let failed = text(&session.command_line("b1 COPY 1:2 Archive"));
	assert!(failed.contains("b1 NO"), "{failed}");
	assert_eq!(archived(dir.path()), 0, "the first copy was taken back");
}

/// Sessions of one account that COPY at the same moment: only the check
/// made under the account's admission lock keeps the account within its
/// quota.
fn round() -> (usize, u64) {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), &message(0));
	// The source plus three copies fit, a fourth copy does not.
	let fits = 3;
	let limit = (MESSAGE_BYTES * (fits + 1) + MESSAGE_BYTES / 2) as u64;
	let sessions: Vec<Session> = (0..SESSIONS).map(|_| session(dir.path(), limit)).collect();
	let start = std::sync::Arc::new(std::sync::Barrier::new(SESSIONS));
	let copied: usize = sessions
		.into_iter()
		.map(|mut session| {
			let start = start.clone();
			std::thread::spawn(move || {
				start.wait();
				let done = text(&session.command_line("b1 COPY 1 Archive"));
				if done.contains("b1 OK") {
					1
				} else {
					assert!(done.contains("b1 NO [OVERQUOTA]"), "{done}");
					0
				}
			})
		})
		.collect::<Vec<_>>()
		.into_iter()
		.map(|handle| handle.join().expect("session"))
		.sum();
	assert_eq!(archived(dir.path()), copied);
	let stored = usage(dir.path());
	assert!(stored <= limit, "{stored} bytes stored, quota {limit}");
	(copied, stored)
}

#[test]
fn copies_at_the_same_moment_stop_at_the_quota() {
	for _ in 0..ROUNDS {
		let (copied, _) = round();
		assert_eq!(copied, 3, "every round must copy as many as fit");
	}
}
