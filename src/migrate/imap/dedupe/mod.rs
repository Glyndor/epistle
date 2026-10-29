//! Recognising a message that is already stored locally, for the runs that
//! cannot trust UIDs: after the remote UIDVALIDITY changed, or after a run
//! that died while writing a batch.
//!
//! A message is identified by its Message-ID and its size; one without a
//! Message-ID by the SHA-256 of its octets and its size. The index counts
//! copies, and each remote message that matches uses one up, so two
//! identical messages in the source still end up as two locally.

use std::path::Path;

use super::MigrateError;
use super::metadata::Budget;
use crate::imap::mailbox;
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

mod disk;

/// The 32-byte identity fingerprint the index compares. The ledger of
/// confirmed messages keeps one per message, so a message that is not
/// downloaded again can still consume its copy of the local mailbox.
pub(crate) fn fingerprint(key: &Key) -> [u8; 32] {
	disk::Table::digest(key)
}

/// The messages already in a local mailbox, indexed without retaining their identities in memory.
#[derive(Debug)]
pub(crate) struct Index {
	table: disk::Table,
}

impl Index {
	/// Index every message in `mailbox`. A mailbox that does not exist yet
	/// is empty. Only a possibly interrupted batch requires fresh durability barriers.
	pub(crate) fn scan(
		data_dir: &Path,
		account: &str,
		mailbox: &str,
		crypto: &MessageCrypto,
		budget: &mut Budget,
		body_limit: usize,
		sync_pending: bool,
	) -> Result<Self, MigrateError> {
		use std::io::Read;
		use std::os::unix::fs::OpenOptionsExt;
		budget.charge(16 * 1024)?;
		let dir = mailbox::mailbox_dir(data_dir, account, mailbox).ok_or_else(|| {
			MigrateError::Storage(std::io::Error::other("invalid recovery mailbox"))
		})?;
		let entries = || -> std::io::Result<_> {
			match std::fs::read_dir(&dir) {
				Ok(entries) => Ok(Some(entries)),
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
				Err(error) => Err(error),
			}
		};
		let count = entries()
			.map_err(MigrateError::Storage)?
			.into_iter()
			.flatten()
			.try_fold(0u64, |count, entry| entry.map(|_| count.saturating_add(1)))
			.map_err(MigrateError::Storage)?;
		let file = super::state::scratch(data_dir).map_err(MigrateError::Storage)?;
		let mut index = Index {
			table: disk::Table::new(file, count).map_err(MigrateError::Storage)?,
		};
		let mut synced = false;
		// Avoid Snapshot::open: it collects every local message and its flags
		// before the recovery index can apply any memory limit.
		for entry in entries()
			.map_err(MigrateError::Storage)?
			.into_iter()
			.flatten()
		{
			let entry = entry.map_err(MigrateError::Storage)?;
			budget.check_deadline()?;
			let path = entry.path();
			if path.extension().is_none_or(|ext| ext != "eml")
				|| path
					.file_stem()
					.and_then(|s| s.to_str())
					.and_then(|s| uuid::Uuid::parse_str(s).ok())
					.is_none()
			{
				continue;
			}
			let read = || -> std::io::Result<Vec<u8>> {
				let file = std::fs::OpenOptions::new()
					.read(true)
					.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
					.open(&path)?;
				if !file.metadata()?.is_file() {
					return Err(std::io::Error::other(
						"recovery message must be a regular file",
					));
				}
				let limit = body_limit.saturating_add(crate::storage::OVERHEAD);
				let mut bytes = Vec::new();
				file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
				if bytes.len() > limit {
					return Err(std::io::Error::other(
						"recovery message exceeds the message size limit; saved progress is retained",
					));
				}
				let body = crypto.decode(&bytes)?;
				if body.len() > body_limit {
					return Err(std::io::Error::other(
						"recovery message exceeds the message size limit; saved progress is retained",
					));
				}
				Ok(body)
			};
			let body = read().map_err(MigrateError::Storage)?;
			let key = key(&body);
			let id = path
				.file_stem()
				.and_then(|s| s.to_str())
				.and_then(|s| uuid::Uuid::parse_str(s).ok())
				.expect("validated message UUID");
			if sync_pending {
				super::durability::files(data_dir, account, mailbox, id)
					.map_err(MigrateError::Storage)?;
				synced = true;
			}
			index.table.add(&key).map_err(MigrateError::Storage)?;
		}
		// The directories are shared by every message, so they are made durable
		// once for the whole scan and not once for each message.
		if synced {
			super::durability::hierarchy(data_dir, account, mailbox)
				.map_err(MigrateError::Storage)?;
		}
		Ok(index)
	}

	/// Whether a stored copy of `key` is still unclaimed; claims it.
	pub(crate) fn claim(&mut self, key: &Key) -> std::io::Result<bool> {
		self.table.claim(key)
	}

	/// Whether a stored copy of `fingerprint` is still unclaimed; claims it.
	pub(crate) fn claim_fingerprint(&mut self, fingerprint: &[u8; 32]) -> std::io::Result<bool> {
		self.table.claim_hash(fingerprint)
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
mod tests;
