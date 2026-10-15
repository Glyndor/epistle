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

use super::chain::{CHAIN_DIR, day_file, open_day};
use super::day::Day;
use super::lines::{Line, Lines};
use super::record::{MAX_RECORDS_PER_DAY, Position, Record, hash_from_hex, to_hex};

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
	/// The `prev` of the first record.
	pub first_prev: [u8; 32],
	/// Where the last record leaves the chain.
	pub last: Position,
}

/// Walk the records of `day`, expecting the first to follow `expected`
/// (any position when `None`), calling `visit` with each record and the
/// hash of its line.
///
/// Every field read is checked: the line must be the canonical encoding of
/// its record (so two byte strings never stand for one record), the
/// version known, the sequence number one more than the record before, the
/// time no earlier than it and inside `day`, and the day no longer than
/// [`MAX_RECORDS_PER_DAY`]. An empty day file, and a day file that is a
/// symbolic link, are refused.
pub fn walk_day(
	evidence_root: &Path,
	day: Day,
	expected: Option<Position>,
	mut visit: impl FnMut(u64, &Record, &[u8; 32]),
) -> Result<DayWalk, Break> {
	let at = |line: u64, problem: Problem| Break { day, line, problem };
	let path = day_file(&evidence_root.join(CHAIN_DIR), day);
	let file =
		open_day(&path).map_err(|error| at(0, Problem::Unreadable(error.kind().to_string())))?;
	let mut lines = Lines::new(BufReader::new(file));
	let mut expected = expected;
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
		if records == MAX_RECORDS_PER_DAY {
			return Err(at(
				number,
				Problem::Malformed("more records than any day may hold".into()),
			));
		}
		let record =
			Record::parse_canonical(bytes).map_err(|why| at(number, Problem::Malformed(why)))?;
		let prev = hash_from_hex(&record.prev)
			.ok_or_else(|| at(number, Problem::Malformed("prev is not a SHA-256".into())))?;
		if Day::of_epoch(record.time) != day {
			return Err(at(
				number,
				Problem::Malformed("the record's time is not in this day".into()),
			));
		}
		if let Some(expected) = expected {
			if prev != expected.hash {
				return Err(at(
					number,
					Problem::Unchained {
						expected: to_hex(&expected.hash),
						found: record.prev.clone(),
					},
				));
			}
			if record.seq != expected.seq + 1 {
				return Err(at(
					number,
					Problem::Malformed(format!("sequence {} follows {}", record.seq, expected.seq)),
				));
			}
			if record.time < expected.time {
				return Err(at(
					number,
					Problem::Malformed("the time goes backwards".into()),
				));
			}
		}
		let position = record.position(bytes);
		first_prev.get_or_insert(prev);
		visit(number, &record, &position.hash);
		expected = Some(position);
		records += 1;
	}
	match (first_prev, expected) {
		(Some(first_prev), Some(last)) => Ok(DayWalk {
			records,
			first_prev,
			last,
		}),
		_ => Err(at(0, Problem::Malformed("empty day file".into()))),
	}
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "verify_tests_fields.rs"]
mod tests_fields;
