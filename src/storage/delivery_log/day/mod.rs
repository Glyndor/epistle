//! Reading one day of the delivery log, record by record.
//!
//! The warm-up judges each receiver group on the records of one UTC day.
//! A busy day is a large file, so it is read a line at a time and never
//! held whole; a line longer than [`MAX_LINE`] is not one this server wrote
//! and is skipped, as is a line that does not parse.

use std::io::{BufRead, BufReader, Read};

use super::{Day, DeliveryLog, DeliveryRecord};

/// The longest line read back. A record is metadata only: a reply cut to
/// 200 bytes and the caller's correlation map, far below this.
pub const MAX_LINE: usize = 64 * 1024;

/// The `YYYY-MM-DD` name of the UTC day `unix_day` days after 1970-01-01.
pub fn day_name(unix_day: i64) -> String {
	Day::from_unix_days(unix_day).to_string()
}

impl DeliveryLog {
	/// Call `visit` with every record of the UTC day `unix_day`, in the
	/// order they were written. A day with no file has no records. Returns
	/// how many lines were skipped because they were too long or did not
	/// parse.
	pub fn for_each_on_day(
		&self,
		unix_day: i64,
		mut visit: impl FnMut(&DeliveryRecord),
	) -> std::io::Result<u64> {
		let path = self.path_for_day(Day::from_unix_days(unix_day))?;
		let file = match std::fs::File::open(&path) {
			Ok(file) => file,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
			Err(error) => return Err(error),
		};
		let mut reader = BufReader::new(file);
		let mut line = Vec::new();
		let mut skipped = 0;
		loop {
			line.clear();
			// One byte past the limit tells a line at the limit from a
			// longer one; the rest of a longer line is then drained.
			let read = (&mut reader)
				.take(MAX_LINE as u64 + 1)
				.read_until(b'\n', &mut line)?;
			if read == 0 {
				return Ok(skipped);
			}
			if line.last() != Some(&b'\n') && line.len() > MAX_LINE {
				skipped += 1;
				drain_line(&mut reader)?;
				continue;
			}
			let text = line.strip_suffix(b"\n").unwrap_or(&line);
			if text.is_empty() {
				continue;
			}
			match serde_json::from_slice::<DeliveryRecord>(text) {
				Ok(record) => visit(&record),
				Err(_) => skipped += 1,
			}
		}
	}
}

/// Read and drop the rest of a line, a buffer at a time.
fn drain_line(reader: &mut impl BufRead) -> std::io::Result<()> {
	loop {
		let buffer = reader.fill_buf()?;
		if buffer.is_empty() {
			return Ok(());
		}
		match buffer.iter().position(|byte| *byte == b'\n') {
			Some(at) => {
				reader.consume(at + 1);
				return Ok(());
			}
			None => {
				let length = buffer.len();
				reader.consume(length);
			}
		}
	}
}

#[cfg(test)]
mod tests;

/// Whether `year-month-day` is a day of the calendar: the month has that many
/// days (February 29 only in a leap year) and the year is one a four-digit
/// date can name.
pub(super) fn is_calendar_day(year: i64, month: u64, day: u64) -> bool {
	let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
	let length = match month {
		1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
		4 | 6 | 9 | 11 => 30,
		2 if leap => 29,
		2 => 28,
		_ => return false,
	};
	(1970..=9999).contains(&year) && (1..=length).contains(&day)
}

/// Whether a UTC offset in seconds is one a clock uses: at most 23:59.
pub(super) fn is_clock_offset(seconds: i64) -> bool {
	(0..24 * 3600).contains(&seconds)
}
