//! UTC calendar days, the unit evidence files and checkpoints are cut by.
//!
//! A day is days since 1970-01-01 in UTC. File names are always rendered
//! from this number, never taken from input, and a name read back from
//! disk is accepted only when it renders to itself, so `2026-02-30` or
//! `../x` never names a day.

pub mod state;

/// `0000-01-01` and `9999-12-31` as days since 1970-01-01.
const FIRST_NAMED: i64 = -719_528;
const LAST_NAMED: i64 = 2_932_896;

/// One UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Day(pub i64);

impl Day {
	/// The UTC day that contains `epoch` (seconds since the Unix epoch).
	pub fn of_epoch(epoch: u64) -> Self {
		let secs = i64::try_from(epoch).unwrap_or(i64::MAX);
		Day(secs.div_euclid(86_400))
	}

	/// Epoch seconds of the first second of this day.
	pub fn start_epoch(self) -> u64 {
		u64::try_from(self.0.saturating_mul(86_400)).unwrap_or(0)
	}

	/// The day before this one.
	pub fn previous(self) -> Self {
		Day(self.0 - 1)
	}

	/// `YYYY-MM-DD`. A day outside the years 0000 to 9999, which no clock
	/// has a reason to name, is shown as the nearest one that exists, so a
	/// name can always be made.
	pub fn name(self) -> String {
		crate::storage::delivery_log::day_name(self.0.clamp(FIRST_NAMED, LAST_NAMED))
	}

	/// The day named `YYYY-MM-DD`, or `None` for anything that is not a
	/// real calendar date in that exact form.
	pub fn parse(value: &str) -> Option<Self> {
		let bytes = value.as_bytes();
		if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
			return None;
		}
		let digits = |range: std::ops::Range<usize>| -> Option<i64> {
			let part = &value[range];
			if !part.bytes().all(|byte| byte.is_ascii_digit()) {
				return None;
			}
			part.parse().ok()
		};
		let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
		if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
			return None;
		}
		let parsed = Day(days_from_civil(year, month, day));
		(parsed.name() == value).then_some(parsed)
	}
}

impl std::fmt::Display for Day {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(&self.name())
	}
}

/// Howard Hinnant's `days_from_civil` (public domain).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
	let year = if month <= 2 { year - 1 } else { year };
	let era = if year >= 0 { year } else { year - 399 } / 400;
	let year_of_era = year - era * 400;
	let shifted = if month > 2 { month - 3 } else { month + 9 };
	let day_of_year = (153 * shifted + 2) / 5 + day - 1;
	let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
	era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests;
