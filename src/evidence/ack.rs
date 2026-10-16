//! An operator's acknowledgement of a break in the evidence.
//!
//! While the evidence does not verify, new transactional mail is refused:
//! its evidence would be appended to a chain that cannot prove anything.
//! The operator lifts that with `epistle evidence acknowledge`, run on the
//! server by root or by the owner of the data directory; nothing else
//! (the API, the mail listeners) can make one.
//!
//! An acknowledgement is its own record in the chain. It names the exact
//! break (day, line, and the SHA-256 of its description), the reason and the
//! operator (uid, user, host), and carries an Ed25519 signature by the
//! pinned evidence key over those fields. It counts only when it sits in the
//! chain after the break it names and its signature verifies; a dropped
//! file, an edited record or a different break counts for nothing.

use std::io::BufReader;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::chain::{CHAIN_DIR, Chain, day_file, open_day};
use super::key::{self, EvidenceKey};
use super::lines::{Line, Lines};
use super::record::{Entry, Record, bounded, hash_from_hex, sha256, to_hex};
use super::verify::Break;

/// The record an acknowledgement leaves in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledged {
	/// The day of the break (`YYYY-MM-DD`).
	pub break_day: String,
	/// Its line, `0` for the day as a whole.
	pub break_line: u64,
	/// Hex SHA-256 of the break's description.
	pub break_id: String,
	/// Why the operator accepts it.
	pub reason: String,
	/// Who acknowledged it: uid, user and host.
	pub operator: String,
	/// The id of the key that signed it.
	pub key: String,
	/// Hex Ed25519 signature over [`statement`].
	pub signature: String,
}

/// Who runs the command: the real uid, the user that asked for it through
/// `sudo` when there is one, and the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator(String);

impl Operator {
	/// The operator of this process. Refused unless the process runs as root
	/// or as the owner of `evidence_root`.
	pub fn current(evidence_root: &Path) -> std::io::Result<Operator> {
		use std::os::unix::fs::MetadataExt;
		// SAFETY: getuid and geteuid have no preconditions and cannot fail.
		let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
		let owner = std::fs::metadata(evidence_root)?.uid();
		if euid != 0 && euid != owner {
			return Err(std::io::Error::new(
				std::io::ErrorKind::PermissionDenied,
				"only root or the owner of the data directory may acknowledge a break",
			));
		}
		let sudo = std::env::var("SUDO_USER").unwrap_or_default();
		let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
		Ok(Operator(bounded(&format!(
			"uid={uid} sudo_user={} host={}",
			printable(&sudo),
			printable(host.trim())
		))))
	}

	/// An operator named explicitly, for tests.
	#[cfg(test)]
	pub(crate) fn named(name: &str) -> Operator {
		Operator(name.to_string())
	}

	/// The operator as recorded.
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

fn printable(value: &str) -> String {
	value
		.chars()
		.filter(|c| c.is_ascii_graphic())
		.take(64)
		.collect()
}

/// The id of a break: the SHA-256 of its description.
pub fn id(at: &Break) -> String {
	to_hex(&sha256(at.to_string().as_bytes()))
}

/// The bytes an acknowledgement signs.
pub fn statement(record: &Acknowledged) -> Vec<u8> {
	format!(
		"epistle evidence acknowledgement\n{}\n{}\n{}\n{}\n{}\n{}\n",
		record.break_day,
		record.break_line,
		record.break_id,
		record.reason,
		record.operator,
		record.key
	)
	.into_bytes()
}

/// Acknowledge `at` for `reason` as `operator`: sign it and append it to the
/// chain.
pub fn acknowledge(
	evidence_root: &Path,
	key: &EvidenceKey,
	at: &Break,
	reason: &str,
	operator: &Operator,
) -> std::io::Result<()> {
	let record = signed(key, at, reason, operator);
	Chain::open(evidence_root)?.append(Entry::Acknowledged(record))?;
	Ok(())
}

/// [`acknowledge`] at a fixed time, for tests.
#[cfg(test)]
pub(crate) fn acknowledge_at(
	evidence_root: &Path,
	key: &EvidenceKey,
	at: &Break,
	reason: &str,
	operator: &Operator,
	now: u64,
) -> std::io::Result<()> {
	let record = signed(key, at, reason, operator);
	Chain::open(evidence_root)?.append_at(now, Entry::Acknowledged(record))?;
	Ok(())
}

fn signed(key: &EvidenceKey, at: &Break, reason: &str, operator: &Operator) -> Acknowledged {
	let mut record = Acknowledged {
		break_day: at.day.name(),
		break_line: at.line,
		break_id: id(at),
		reason: bounded(
			&reason
				.chars()
				.filter(|c| !c.is_control())
				.collect::<String>(),
		),
		operator: operator.0.clone(),
		key: key.id(),
		signature: String::new(),
	};
	record.signature = to_hex(&key.sign(&statement(&record)));
	record
}

/// Whether `at` is acknowledged: a record in the chain after it names it,
/// and is signed by the pinned evidence key or by one it took over from by a
/// signed rotation (an acknowledgement made before a rotation still counts).
pub fn is_acknowledged(evidence_root: &Path, at: &Break) -> bool {
	let Ok(lineage) = super::rotation::lineage(evidence_root) else {
		return false;
	};
	let keys_dir = evidence_root.join(key::KEYS_DIR);
	let wanted = id(at);
	let Ok(days) = Chain::open(evidence_root).and_then(|chain| chain.days()) else {
		return false;
	};
	for day in days.into_iter().filter(|day| *day >= at.day) {
		let Ok(file) = open_day(&day_file(&evidence_root.join(CHAIN_DIR), day)) else {
			continue;
		};
		let mut lines = Lines::new(BufReader::new(file));
		while let Ok(Some((number, line))) = lines.next_line() {
			let Line::Complete(bytes) = line else {
				continue;
			};
			if day == at.day && number <= at.line {
				continue;
			}
			let Ok(Record {
				entry: Entry::Acknowledged(record),
				..
			}) = Record::parse_canonical(bytes)
			else {
				continue;
			};
			let valid = record.break_id == wanted
				&& record.break_day == at.day.name()
				&& record.break_line == at.line
				&& lineage.contains(&record.key)
				&& super::rotation::public_key(&keys_dir, &record.key)
					.zip(decode_signature(&record.signature))
					.is_some_and(|(public, signature)| {
						key::verify(&public, &statement(&record), &signature)
					});
			if valid {
				return true;
			}
		}
	}
	false
}

/// The 64 bytes of a hex Ed25519 signature.
fn decode_signature(hex: &str) -> Option<Vec<u8>> {
	if hex.len() != 128 {
		return None;
	}
	let (left, right) = hex.split_at(64);
	let mut out = hash_from_hex(left)?.to_vec();
	out.extend_from_slice(&hash_from_hex(right)?);
	Some(out)
}

#[cfg(test)]
#[path = "ack_tests.rs"]
mod tests;
