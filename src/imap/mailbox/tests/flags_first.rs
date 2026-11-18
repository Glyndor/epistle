//! An appended message is never visible before its flags file: a reader
//! that lists the mailbox and finds the `.eml` also finds the `.flags`.

use std::sync::Barrier;

use super::*;
use crate::storage::MessageCrypto;

/// How many appends are raced against a reader.
const ROUNDS: usize = 150;

#[test]
fn a_visible_message_already_has_its_flags_file() {
	for _ in 0..ROUNDS {
		let dir = tempfile::tempdir().expect("tempdir");
		create(dir.path(), "alice", "Sent").expect("create");
		let mailbox = dir
			.path()
			.join("accounts")
			.join("alice")
			.join("folders")
			.join("Sent");
		let start = Barrier::new(2);
		std::thread::scope(|scope| {
			let reader = scope.spawn(|| {
				start.wait();
				loop {
					let eml = std::fs::read_dir(mailbox.join("new"))
						.ok()
						.and_then(|entries| {
							entries
								.flatten()
								.map(|entry| entry.path())
								.find(|path| path.extension().is_some_and(|ext| ext == "eml"))
						});
					if let Some(eml) = eml {
						return std::fs::read_to_string(eml.with_extension("flags"));
					}
					std::thread::yield_now();
				}
			});
			start.wait();
			append(
				dir.path(),
				"alice",
				"Sent",
				&[Flag::Seen],
				b"sent\r\n",
				&MessageCrypto::disabled(),
			)
			.expect("append");
			let flags = reader.join().expect("reader");
			assert!(flags.expect("flags file exists").contains("seen"));
		});
	}
}
