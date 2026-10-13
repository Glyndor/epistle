//! Recognising a message that is already stored locally, for the runs that
//! cannot trust UIDs: after the remote UIDVALIDITY changed, or after a run
//! that died while writing a batch.
//!
//! A message is identified by its Message-ID and its size; one without a
//! Message-ID by the SHA-256 of its octets and its size. The index counts
//! copies, and each remote message that matches uses one up, so two
//! identical messages in the source still end up as two locally.

use std::collections::HashMap;
use std::path::Path;

use crate::imap::mailbox::Snapshot;
use crate::storage::MessageCrypto;

/// How far into a message the Message-ID header is looked for.
const HEADER_SCAN_BYTES: usize = 256 * 1024;

/// The identity of a message for deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Key {
	/// The Message-ID (as written, angle brackets included) and the size.
	MessageId(Vec<u8>, usize),
	/// SHA-256 of the octets and the size, for a message without one.
	Digest([u8; 32], usize),
}

/// The identity of `message`.
pub(crate) fn key(message: &[u8]) -> Key {
	match message_id(message) {
		Some(id) => Key::MessageId(id, message.len()),
		None => {
			let digest = ring::digest::digest(&ring::digest::SHA256, message);
			let mut bytes = [0u8; 32];
			bytes.copy_from_slice(digest.as_ref());
			Key::Digest(bytes, message.len())
		}
	}
}

/// The messages already in a local mailbox, counted by identity.
#[derive(Debug, Default)]
pub(crate) struct Index {
	counts: HashMap<Key, u32>,
}

impl Index {
	/// Index every message in `mailbox`. A mailbox that does not exist yet
	/// is empty.
	pub(crate) fn scan(
		data_dir: &Path,
		account: &str,
		mailbox: &str,
		crypto: &MessageCrypto,
	) -> std::io::Result<Self> {
		let mut index = Index::default();
		if !crate::imap::mailbox::exists(data_dir, account, mailbox) {
			return Ok(index);
		}
		let snapshot = Snapshot::open(data_dir, account, mailbox, crypto)?;
		for message in snapshot.messages() {
			let body = snapshot.read(message)?;
			index.add(key(&body));
		}
		Ok(index)
	}

	/// Count one more stored copy of `key`.
	pub(crate) fn add(&mut self, key: Key) {
		*self.counts.entry(key).or_default() += 1;
	}

	/// Whether a stored copy of `key` is still unclaimed; claims it.
	pub(crate) fn claim(&mut self, key: &Key) -> bool {
		match self.counts.get_mut(key) {
			Some(count) if *count > 0 => {
				*count -= 1;
				true
			}
			_ => false,
		}
	}
}

/// The value of the first Message-ID header, trimmed, if the header block
/// has one. Folded continuation lines are joined. Linear in the header
/// size, which is capped at [`HEADER_SCAN_BYTES`].
pub(crate) fn message_id(message: &[u8]) -> Option<Vec<u8>> {
	let header = &message[..message.len().min(HEADER_SCAN_BYTES)];
	let mut lines = header.split(|&b| b == b'\n').peekable();
	while let Some(line) = lines.next() {
		let line = line.strip_suffix(b"\r").unwrap_or(line);
		if line.is_empty() {
			return None;
		}
		let Some(colon) = line.iter().position(|&b| b == b':') else {
			continue;
		};
		if !line[..colon].eq_ignore_ascii_case(b"message-id") {
			continue;
		}
		let mut value = line[colon + 1..].to_vec();
		while let Some(next) = lines.peek() {
			if !next.first().is_some_and(|&b| b == b' ' || b == b'\t') {
				break;
			}
			let next = lines.next().unwrap_or_default();
			value.extend_from_slice(next.strip_suffix(b"\r").unwrap_or(next));
		}
		let trimmed = value.trim_ascii();
		return (!trimmed.is_empty()).then(|| trimmed.to_vec());
	}
	None
}

#[cfg(test)]
#[path = "dedupe_tests.rs"]
mod tests;
