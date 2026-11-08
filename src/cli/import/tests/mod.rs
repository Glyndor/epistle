//! The tests of the import: the limit that bounds every entry, the entries
//! it refuses, and the memory an import takes.

#[allow(unused_imports)]
pub use super::*;

pub(super) mod boundary;
pub(super) mod maildir;
pub(super) mod mbox;

/// A data directory with an account in it.
pub(super) fn account_dir() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	dir
}

/// The message an entry of `size` bytes carries: the headers, the body and
/// the CRLF that ends it.
pub(super) fn message_of(size: usize) -> Vec<u8> {
	const HEADER: &str = "Subject: x\r\n\r\n";
	let body = size - HEADER.len() - 2;
	let mut message = Vec::from(HEADER.as_bytes());
	message.extend(std::iter::repeat_n(b'b', body));
	message.extend_from_slice(b"\r\n");
	message
}

/// One mbox entry whose message is exactly `size` bytes: the `From ` line
/// that starts it, the message, and the blank line that ends it.
pub(super) fn entry_of(size: usize) -> Vec<u8> {
	let mut entry = Vec::from(b"From MAILER-DAEMON@localhost\r\n");
	entry.extend_from_slice(&message_of(size));
	entry.extend_from_slice(b"\r\n");
	entry
}

/// One mbox entry whose message is exactly `size` bytes and is made of many
/// lines: an entry that goes past the limit is refused as a whole, not
/// because one of its lines is long.
pub(super) fn entry_of_lines(size: usize) -> Vec<u8> {
	const HEADER: &str = "Subject: x\r\n\r\n";
	let mut message = Vec::from(HEADER.as_bytes());
	let mut left = size - HEADER.len();
	while left > 0 {
		let take = if left > 64 {
			62
		} else {
			left.saturating_sub(2)
		};
		message.extend(std::iter::repeat_n(b'b', take));
		message.extend_from_slice(b"\r\n");
		left -= take + 2;
	}
	assert_eq!(message.len(), size, "the message is exactly the size asked");
	let mut entry = Vec::from(b"From MAILER-DAEMON@localhost\r\n");
	entry.extend_from_slice(&message);
	entry.extend_from_slice(b"\r\n");
	entry
}

/// The messages stored in the account's INBOX.
pub(super) fn stored(dir: &std::path::Path) -> Vec<Vec<u8>> {
	let snapshot = crate::imap::mailbox::Snapshot::open(
		dir,
		"alice",
		"INBOX",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("snapshot");
	snapshot
		.messages()
		.map(|message| snapshot.read(message).expect("read"))
		.collect()
}
