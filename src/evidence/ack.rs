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
use super::day_state::day_state;
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
	/// The digest of the day as the operator saw it (see
	/// [`super::day_state::day_state`]), for a break found while walking a
	/// day. Empty for a break that names its own state.
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub state: String,
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
	let mut text = format!(
		"epistle evidence acknowledgement\n{}\n{}\n{}\n{}\n{}\n{}\n",
		record.break_day,
		record.break_line,
		record.break_id,
		record.reason,
		record.operator,
		record.key
	);
	if !record.state.is_empty() {
		text.push_str(&format!("state {}\n", record.state));
	}
	text.into_bytes()
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
	let record = signed(key, at, reason, operator, state_of(evidence_root, at)?);
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
	let record = signed(key, at, reason, operator, state_of(evidence_root, at)?);
	Chain::open(evidence_root)?.append_at(now, Entry::Acknowledged(record))?;
	Ok(())
}

/// The state of the day the operator is accepting a break in, for a break
/// found while walking it; a break judged from the whole chain names its own.
fn state_of(evidence_root: &Path, at: &Break) -> std::io::Result<String> {
	match at.names_state() {
		true => Ok(String::new()),
		false => day_state(evidence_root, at.day, None),
	}
}

fn signed(
	key: &EvidenceKey,
	at: &Break,
	reason: &str,
	operator: &Operator,
	state: String,
) -> Acknowledged {
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
		state,
		signature: String::new(),
	};
	record.signature = to_hex(&key.sign(&statement(&record)));
	record
}

/// Whether `at` is acknowledged: a record in the chain after it names it,
/// and is signed by the evidence key in force at its place in the chain (an
/// acknowledgement made before a rotation still counts).
pub fn is_acknowledged(evidence_root: &Path, at: &Break) -> bool {
	let Ok(timeline) = super::rotation::Timeline::load(evidence_root) else {
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
				&& timeline.check(&record.key, (day, number)).is_ok()
				&& saw_the_day_as_it_is(evidence_root, at, &record, (day, number))
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

/// The most breaks of one day [`walk_day_acknowledged`] goes past.
const MAX_PAST_PER_DAY: usize = 64;

/// [`super::verify::walk_day`], going on past the breaks an operator
/// acknowledged, as the verification does, so a reader of the chain sees the
/// records after one. Any other break is returned: a reader that decides
/// something from what it saw must not take a day it could not read for one
/// that holds nothing. `visit` is called again from the start of the day
/// after each break gone past, so it must not count.
pub fn walk_day_acknowledged(
	evidence_root: &Path,
	day: super::day::Day,
	mut visit: impl FnMut(u64, &Record, &[u8; 32]),
) -> Result<super::verify::DayWalk, Break> {
	let mut accepted: Vec<u64> = Vec::new();
	loop {
		match super::verify::walk_day_accepting(evidence_root, day, None, &accepted, &mut visit) {
			Err(at)
				if at.line > 0
					&& accepted.len() < MAX_PAST_PER_DAY
					&& !accepted.contains(&at.line)
					&& is_acknowledged(evidence_root, &at) =>
			{
				accepted.push(at.line);
			}
			walked => return walked,
		}
	}
}

/// Whether the state `record` names is the one the day is in now: every
/// line before the acknowledgement (all of them when it sits in a later day)
/// and the checkpoint files. A break that names its own state carries none.
fn saw_the_day_as_it_is(
	evidence_root: &Path,
	at: &Break,
	record: &Acknowledged,
	(day, number): (super::day::Day, u64),
) -> bool {
	if at.names_state() {
		return record.state.is_empty();
	}
	let before = (day == at.day).then_some(number);
	!record.state.is_empty()
		&& day_state(evidence_root, at.day, before).is_ok_and(|state| state == record.state)
}

/// The 64 bytes of a hex Ed25519 signature.
fn decode_signature(hex: &str) -> Option<Vec<u8>> {
	// 128 ASCII bytes: split in the middle of a character would panic.
	if hex.len() != 128 || !hex.is_ascii() {
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
#[cfg(test)]
#[path = "ack_tests_state.rs"]
mod tests_state;
