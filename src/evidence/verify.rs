//! Walking the evidence chain and reporting the first place it breaks.
//!
//! Every line is hashed as it is on disk and compared with the `prev` of the
//! line after it, across day files. An edited record changes its hash, so
//! the next record no longer points at it; a deleted, reordered or inserted
//! record leaves a `prev` that names something other than the line before
//! it. The walk stops at the first break and says where it is: the day, the
//! line, and both hashes. Lines are read one at a time, so a day of any size
//! is verified in constant memory.

use std::io::BufReader;
use std::path::Path;

use super::chain::{CHAIN_DIR, day_file};
use super::day::Day;
use super::lines::{Line, Lines};
use super::record::{FORMAT_VERSION, GENESIS, Record, hash_from_hex, sha256, to_hex};

/// Where and how the evidence stops verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Break {
	/// The day file.
	pub day: Day,
	/// The 1-based line, `0` for a problem with the day as a whole.
	pub line: u64,
	/// What is wrong.
	pub problem: Problem,
}

/// What can be wrong with the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
	/// The line does not point at the line before it.
	Unchained {
		/// Hex hash the line should name as `prev`.
		expected: String,
		/// Hex hash it names.
		found: String,
	},
	/// The line is not a record of a known format.
	Malformed(String),
	/// The line is longer than any record this server writes.
	TooLong,
	/// The last line has no newline: a write that never completed.
	Torn,
	/// The day's checkpoint does not match the day, or its signature or
	/// timestamp does not verify.
	Checkpoint(String),
	/// The day file could not be read.
	Unreadable(String),
}

impl std::fmt::Display for Break {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let at = if self.line == 0 {
			self.day.name()
		} else {
			format!("{} line {}", self.day, self.line)
		};
		match &self.problem {
			Problem::Unchained { expected, found } if self.line == 1 => write!(
				formatter,
				"{at}: the day does not follow the day before (prev {found}, expected {expected}): \
				 a day is missing, or a day was rewritten"
			),
			Problem::Unchained { expected, found } => write!(
				formatter,
				"{at}: record does not chain onto the one before it (prev {found}, expected {expected}): \
				 a record was edited, deleted, reordered or inserted"
			),
			Problem::Malformed(why) => write!(formatter, "{at}: not an evidence record ({why})"),
			Problem::TooLong => write!(formatter, "{at}: line longer than any evidence record"),
			Problem::Torn => write!(
				formatter,
				"{at}: incomplete last record (interrupted write)"
			),
			Problem::Checkpoint(why) => write!(formatter, "{at}: checkpoint: {why}"),
			Problem::Unreadable(why) => write!(formatter, "{at}: cannot read the day file ({why})"),
		}
	}
}

/// The result of walking one day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayWalk {
	/// Records in the day.
	pub records: u64,
	/// Hash of the first record's `prev`.
	pub first_prev: [u8; 32],
	/// Hash of the last record, or `first_prev` for an empty day.
	pub last: [u8; 32],
}

/// Walk the records of `day` expecting the first to name `expected_prev`
/// (any value when `None`), calling `visit` with each record and the hash of
/// its line.
pub fn walk_day(
	evidence_root: &Path,
	day: Day,
	expected_prev: Option<[u8; 32]>,
	mut visit: impl FnMut(u64, &Record, &[u8; 32]),
) -> Result<DayWalk, Break> {
	let at = |line: u64, problem: Problem| Break { day, line, problem };
	let path = day_file(&evidence_root.join(CHAIN_DIR), day);
	let file = std::fs::File::open(&path)
		.map_err(|error| at(0, Problem::Unreadable(error.kind().to_string())))?;
	let mut lines = Lines::new(BufReader::new(file));
	let mut expected = expected_prev;
	let mut first_prev = None;
	let mut records = 0u64;
	loop {
		let line = lines
			.next_line()
			.map_err(|error| at(0, Problem::Unreadable(error.kind().to_string())))?;
		let (number, bytes) = match line {
			None => break,
			Some((number, Line::TooLong)) => return Err(at(number, Problem::TooLong)),
			Some((number, Line::Torn(_))) => return Err(at(number, Problem::Torn)),
			Some((number, Line::Complete(bytes))) => (number, bytes),
		};
		let record: Record = serde_json::from_slice(bytes)
			.map_err(|error| at(number, Problem::Malformed(error.to_string())))?;
		if record.v != FORMAT_VERSION {
			return Err(at(
				number,
				Problem::Malformed(format!("format version {}", record.v)),
			));
		}
		let prev = hash_from_hex(&record.prev)
			.ok_or_else(|| at(number, Problem::Malformed("prev is not a SHA-256".into())))?;
		if let Some(expected) = expected
			&& prev != expected
		{
			return Err(at(
				number,
				Problem::Unchained {
					expected: to_hex(&expected),
					found: record.prev.clone(),
				},
			));
		}
		let hash = sha256(bytes);
		first_prev.get_or_insert(prev);
		visit(number, &record, &hash);
		expected = Some(hash);
		records += 1;
	}
	let first_prev = first_prev.or(expected_prev).unwrap_or(GENESIS);
	Ok(DayWalk {
		records,
		first_prev,
		last: expected.unwrap_or(first_prev),
	})
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
