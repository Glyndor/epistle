//! Several sessions of one account that APPEND at the same moment: each one
//! passed the quota check made before its literal was read, and only the
//! check made under the account's admission lock keeps the account within
//! its quota.

use super::*;
use crate::test_fixtures as fixtures;

const MESSAGE_BYTES: usize = 2_000;
const FITS: usize = 3;
const SESSIONS: usize = 12;
const ROUNDS: usize = 12;

fn message() -> Vec<u8> {
	let mut text =
		b"From: a@example.org\r\nTo: alice@example.org\r\nSubject: fill\r\n\r\n".to_vec();
	text.resize(MESSAGE_BYTES, b'x');
	text
}

/// How many of `SESSIONS` sessions are told the message was stored, and the
/// bytes the account holds after they all finished.
fn round() -> (usize, u64) {
	let dir = tempfile::tempdir().expect("tempdir");
	let limit = (MESSAGE_BYTES * FITS + MESSAGE_BYTES / 2) as u64;
	let start = std::sync::Arc::new(std::sync::Barrier::new(SESSIONS));
	let stored: usize = (0..SESSIONS)
		.map(|_| {
			let root = dir.path().to_path_buf();
			let start = start.clone();
			std::thread::spawn(move || {
				let mut session =
					Session::new("mail.example.org", root, directory()).with_quota_limit(limit);
				session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
				let ready =
					text(&session.command_line(&format!("a2 APPEND INBOX {{{MESSAGE_BYTES}}}")));
				assert!(ready.starts_with("+ "), "{ready}");
				start.wait();
				let done = text(&session.literal_done(&message()));
				if done.contains("a2 OK") {
					1
				} else {
					assert!(done.contains("a2 NO [OVERQUOTA]"), "{done}");
					0
				}
			})
		})
		.collect::<Vec<_>>()
		.into_iter()
		.map(|handle| handle.join().expect("session"))
		.sum();
	let usage = crate::imap::mailbox::account_usage(
		dir.path(),
		"alice",
		&crate::storage::MessageCrypto::disabled(),
	);
	assert!(
		usage <= limit,
		"{usage} bytes stored under a quota of {limit}"
	);
	(stored, usage)
}

#[test]
fn appends_at_the_same_moment_stop_at_the_quota() {
	for _ in 0..ROUNDS {
		let (stored, usage) = round();
		assert_eq!(stored, FITS, "{usage} bytes stored");
	}
}
