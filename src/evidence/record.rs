//! The evidence record: one versioned JSON line per event.
//!
//! Every line carries `prev`, the SHA-256 of the line before it (across day
//! files, so the chain is continuous), as lowercase hex. A record's own hash
//! is the SHA-256 of its line bytes as written, without the newline, so a
//! verifier never re-serializes anything: it hashes what is on disk.
//!
//! Records hold metadata only: who sent what, to whom, when, the hash of
//! the exact bytes queued, and what each receiving server answered. The
//! message itself is kept apart, and only when the retention policy says
//! `full`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::MailClass;

/// The version of the line format this build writes and reads.
pub const FORMAT_VERSION: u32 = 1;

/// The `prev` of the first record ever written.
pub const GENESIS: [u8; 32] = [0; 32];

/// The most records one day may hold.
pub const MAX_RECORDS_PER_DAY: u64 = 50_000_000;

/// Where the chain stands after a record: its hash, sequence number and
/// time. The next record must carry `hash` as `prev`, `seq + 1`, and a time
/// no earlier than `time`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
	/// SHA-256 of the record's line.
	pub hash: [u8; 32],
	/// Its sequence number.
	pub seq: u64,
	/// Its time, epoch seconds.
	pub time: u64,
}

impl Position {
	/// Before the first record ever written.
	pub const START: Position = Position {
		hash: GENESIS,
		seq: 0,
		time: 0,
	};
}

/// The longest line a record may take. The largest record is an acceptance
/// with every recipient a submission may carry, far below this.
pub const MAX_LINE: usize = 256 * 1024;

/// Longest Subject, Message-ID or remote reply kept in a record, in bytes.
pub const MAX_FIELD: usize = 998;

/// One line of the evidence log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
	/// Format version ([`FORMAT_VERSION`]).
	pub v: u32,
	/// Position in the chain: one more than the record before it, starting
	/// at 1.
	pub seq: u64,
	/// Hex SHA-256 of the previous line.
	pub prev: String,
	/// Epoch seconds the record was written.
	pub time: u64,
	/// What happened.
	#[serde(flatten)]
	pub entry: Entry,
}

/// The kinds of event the log records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
	/// A message was accepted for sending.
	Accepted(Accepted),
	/// One recipient of an accepted message reached a final outcome.
	Outcome(Outcome),
	/// An acceptance was written but the message never reached the queue
	/// (the server stopped in between): nothing was sent.
	Abandoned(Abandoned),
	/// Older days were purged after their retention.
	Purge(Purge),
	/// An evidence setting changed (for example timestamping).
	Setting(Setting),
	/// An operator acknowledged a break, signed with the evidence key.
	Acknowledged(super::ack::Acknowledged),
}

/// How much of a message is kept, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
	/// `metadata` keeps the record and the hash; `full` keeps the bytes too.
	pub mode: RetentionMode,
	/// Days the record (and the bytes, when kept) must be retained.
	pub days: u32,
}

/// What a retention keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
	/// The record only, with the SHA-256 of the message.
	Metadata,
	/// The record and the exact message bytes.
	Full,
}

/// The acceptance of one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
	/// The queue id of the message.
	pub spool_id: Uuid,
	/// The local account that submitted it.
	pub account: String,
	/// The tenant of the account, when tenants are configured.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tenant: Option<String>,
	/// The class the server granted.
	pub class: MailClass,
	/// The envelope sender.
	pub from: String,
	/// The envelope recipients.
	pub recipients: Vec<String>,
	/// The `Message-ID` field, when present.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub message_id: Option<String>,
	/// The `Date` field, when present.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub date: Option<String>,
	/// The `Subject` field, when present.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub subject: Option<String>,
	/// Hex SHA-256 of the exact bytes handed to the queue (DKIM signed).
	pub sha256: String,
	/// Their length in bytes.
	pub size: u64,
	/// The retention that applied when the message was accepted.
	pub retention: Retention,
}

/// The final outcome for one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
	/// The receiving server accepted the message for this recipient.
	Delivered,
	/// The receiving server refused it for good.
	Bounced,
	/// It could not be delivered before the queue gave up.
	Expired,
	/// The address was on a suppression list and was never contacted.
	Suppressed,
}

/// How the TLS session with the receiving server ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSummary {
	/// The protocol version (`TLSv1_3`).
	pub version: String,
	/// The cipher suite.
	pub cipher: String,
}

/// One recipient's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
	/// The queue id of the message.
	pub spool_id: Uuid,
	/// Its class.
	pub class: MailClass,
	/// The recipient.
	pub recipient: String,
	/// What happened.
	pub result: OutcomeKind,
	/// The attempt that produced it, counting from one; `0` when none was.
	pub attempt: u32,
	/// The receiving server (MX host), when one answered.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub remote: Option<String>,
	/// Its reply, cut to [`MAX_FIELD`] bytes.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reply: Option<String>,
	/// The TLS session, when there was one.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tls: Option<TlsSummary>,
	/// Whether DANE authenticated the receiving server.
	#[serde(default)]
	pub dane: bool,
	/// The MTA-STS mode of the recipient domain, when it published one.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mta_sts: Option<String>,
	/// Days this record must be retained (that of the acceptance).
	pub retain_days: u32,
}

/// An acceptance that never reached the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Abandoned {
	/// The queue id the acceptance named.
	pub spool_id: Uuid,
	/// Why.
	pub reason: String,
	/// Days this record must be retained.
	pub retain_days: u32,
}

/// The note a purge leaves in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Purge {
	/// The last purged day (`YYYY-MM-DD`): every day up to it is gone.
	pub through: String,
	/// Hex SHA-256 of the last record of that day: the `prev` of the first
	/// record kept.
	pub last_hash: String,
	/// Hex SHA-256 of that day's checkpoint file.
	pub checkpoint: String,
	/// Hex SHA-256 of the signed purge statement.
	pub statement: String,
}

/// A change of an evidence setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
	/// The setting (`timestamp`).
	pub name: String,
	/// Its new value.
	pub value: String,
}

impl Entry {
	/// Days a record of this entry must be retained. Purge and setting
	/// notes add nothing of their own: the day they sit in is kept for the
	/// records around them.
	pub fn retain_days(&self) -> u32 {
		match self {
			Entry::Accepted(accepted) => accepted.retention.days,
			Entry::Outcome(outcome) => outcome.retain_days,
			Entry::Abandoned(abandoned) => abandoned.retain_days,
			Entry::Purge(_) | Entry::Setting(_) | Entry::Acknowledged(_) => 0,
		}
	}

	/// The queue id the entry is about, when it is about one message.
	pub fn spool_id(&self) -> Option<Uuid> {
		match self {
			Entry::Accepted(accepted) => Some(accepted.spool_id),
			Entry::Outcome(outcome) => Some(outcome.spool_id),
			Entry::Abandoned(abandoned) => Some(abandoned.spool_id),
			Entry::Purge(_) | Entry::Setting(_) | Entry::Acknowledged(_) => None,
		}
	}
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
	let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
	let mut out = [0u8; 32];
	out.copy_from_slice(digest.as_ref());
	out
}

/// Lowercase hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		out.push(char::from(DIGITS[usize::from(byte >> 4)]));
		out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
	}
	out
}

/// The 32 bytes a 64-digit lowercase hex string names, or `None`.
pub fn hash_from_hex(value: &str) -> Option<[u8; 32]> {
	let bytes = value.as_bytes();
	if bytes.len() != 64 {
		return None;
	}
	let nibble = |digit: u8| match digit {
		b'0'..=b'9' => Some(digit - b'0'),
		b'a'..=b'f' => Some(digit - b'a' + 10),
		_ => None,
	};
	let mut out = [0u8; 32];
	for (index, slot) in out.iter_mut().enumerate() {
		*slot = nibble(bytes[2 * index])? << 4 | nibble(bytes[2 * index + 1])?;
	}
	Some(out)
}

/// `value` cut to at most [`MAX_FIELD`] bytes on a character boundary.
pub fn bounded(value: &str) -> String {
	if value.len() <= MAX_FIELD {
		return value.to_string();
	}
	let mut end = MAX_FIELD;
	while !value.is_char_boundary(end) {
		end -= 1;
	}
	value[..end].to_string()
}

impl Record {
	/// Parse a line, accepting only the exact bytes this build would write
	/// for the record it holds: no unknown or duplicate field, no other key
	/// order, no other spacing or escaping. Two different lines can never
	/// stand for the same record.
	pub fn parse_canonical(line: &[u8]) -> Result<Record, String> {
		let record: Record = serde_json::from_slice(line).map_err(|error| error.to_string())?;
		if record.v != FORMAT_VERSION {
			return Err(format!("format version {}", record.v));
		}
		match record.to_line() {
			Ok(canonical) if canonical == line => Ok(record),
			_ => Err("not in canonical form (unknown, duplicate or reordered fields)".into()),
		}
	}

	/// The position this record, written as `line`, leaves the chain at.
	pub fn position(&self, line: &[u8]) -> Position {
		Position {
			hash: sha256(line),
			seq: self.seq,
			time: self.time,
		}
	}

	/// The line for this record, without the newline, refusing one longer
	/// than [`MAX_LINE`].
	pub fn to_line(&self) -> std::io::Result<Vec<u8>> {
		let line = serde_json::to_vec(self).map_err(std::io::Error::other)?;
		if line.len() > MAX_LINE {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				format!("evidence record of {} bytes exceeds {MAX_LINE}", line.len()),
			));
		}
		Ok(line)
	}
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
