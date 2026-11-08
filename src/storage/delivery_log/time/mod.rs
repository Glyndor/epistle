//! The calendar and the clock of the delivery log.
//!
//! The log keeps one file per day, named `YYYY-MM-DD`, and stamps every
//! record with epoch seconds, so both a date and a timestamp are read and
//! written here: the day a file name carries, the wall clock the log is
//! stamped with, and the `--since` filter the CLI and the API share.
//!
//! The day conversions are Howard Hinnant's public-domain algorithms, kept
//! free of a timezone-aware dependency on purpose: the server stamps every
//! wall-clock value in UTC, and the file name is that UTC day.

use std::time::{SystemTime, UNIX_EPOCH};

use super::day;

/// `YYYY-MM-DD` for the wall clock at `epoch` (seconds since the Unix
/// epoch). The date is the operator's local date in UTC: the log's file
/// name must be derivable from a single timestamp, and the wall clock
/// timezone of the host is what the operator sees.
pub(super) fn date_for_epoch(epoch: u64) -> Day {
	let secs = i64::try_from(epoch).unwrap_or(i64::MAX);
	let days = secs.div_euclid(86_400);
	Day::from_unix_days(days)
}

/// One calendar day in UTC, the file name's date. `packed` is the
/// `YYYY-MM-DD` rendering squashed into one integer for cheap comparison;
/// `unix_days` is the same date as days-since-1970 so the sweep can
/// subtract without re-running the civil-from-days conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Day {
	packed: u32,
	unix_days: i64,
}

impl Day {
	/// Build the day that is `days` days after 1970-01-01.
	pub(super) fn from_unix_days(days: i64) -> Self {
		// Civil-from-days: Howard Hinnant's algorithm, public domain.
		let z = days + 719_468;
		let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
		let doe = (z - era * 146_097) as u64;
		let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
		let y = (yoe as i64) + era * 400;
		let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
		let mp = (5 * doy + 2) / 153;
		let d = doy - (153 * mp + 2) / 5 + 1;
		let m = if mp < 10 { mp + 3 } else { mp - 9 };
		let y = if m <= 2 { y + 1 } else { y };
		Day {
			packed: y as u32 * 10_000 + m as u32 * 100 + d as u32,
			unix_days: days,
		}
	}
}

impl std::fmt::Display for Day {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let y = self.packed / 10_000;
		let m = (self.packed / 100) % 100;
		let d = self.packed % 100;
		write!(formatter, "{y:04}-{m:02}-{d:02}")
	}
}

impl std::str::FromStr for Day {
	type Err = ();
	fn from_str(value: &str) -> Result<Self, Self::Err> {
		let bytes = value.as_bytes();
		if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
			return Err(());
		}
		let y = std::str::from_utf8(&bytes[..4])
			.map_err(|_| ())?
			.parse::<u32>()
			.map_err(|_| ())?;
		let m = std::str::from_utf8(&bytes[5..7])
			.map_err(|_| ())?
			.parse::<u32>()
			.map_err(|_| ())?;
		let d = std::str::from_utf8(&bytes[8..10])
			.map_err(|_| ())?
			.parse::<u32>()
			.map_err(|_| ())?;
		if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
			return Err(());
		}
		let unix_days = days_from_civil(y as i64, m as u64, d as u64);
		Ok(Day {
			packed: y * 10_000 + m * 100 + d,
			unix_days,
		})
	}
}

/// Howard Hinnant's `days_from_civil` (public domain), the inverse of
/// `from_unix_days`. Used to keep the file-name parsing honest: the
/// packed integer is just a rendering, the `unix_days` field is what the
/// sweep subtracts.
fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
	let y = if m <= 2 { y - 1 } else { y };
	let era = if y >= 0 { y } else { y - 399 } / 400;
	let yoe = (y - era * 400) as u64;
	let m = m as i64;
	let d = d as i64;
	let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
	era * 146_097 + doe as i64 - 719_468
}

/// Parse the date out of `<date>.jsonl`. `None` for anything that does not
/// look like a record file; a stray text file in the directory is left
/// alone by the sweep.
pub(super) fn parse_day_filename(name: &str) -> Option<Day> {
	name.strip_suffix(".jsonl")
		.and_then(|stem| stem.parse().ok())
}

/// Whole days from `earlier` to `later`. Saturates to `0` when the order
/// is reversed (which the sweep never asks for, but the function lives
/// on its own).
pub(super) fn days_between(earlier: Day, later: Day) -> u64 {
	let diff = later.unix_days.saturating_sub(earlier.unix_days);
	u64::try_from(diff).unwrap_or(0)
}

/// The wall-clock epoch second the sweep task and the test harness pass in.
pub fn now_epoch() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Parse a `--since` value: either an RFC 3339 timestamp
/// (`2024-01-02T03:04:05Z`, optional fractional seconds) or a duration
/// like `24h` / `7d` / `30m`. Returns the lower-bound epoch second
/// (records with `time >= since` are included) or an error on
/// unparseable input. `None` is returned only for the empty string, the
/// way the CLI / API callers express "no filter".
pub fn parse_since(value: &str, now_epoch: u64) -> Result<Option<u64>, String> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Ok(None);
	}
	if let Some(rest) = trimmed
		.strip_suffix('h')
		.or_else(|| trimmed.strip_suffix('H'))
	{
		return parse_duration_secs(rest, 3600, "h", now_epoch);
	}
	if let Some(rest) = trimmed
		.strip_suffix('d')
		.or_else(|| trimmed.strip_suffix('D'))
	{
		return parse_duration_secs(rest, 86_400, "d", now_epoch);
	}
	if let Some(rest) = trimmed
		.strip_suffix('m')
		.or_else(|| trimmed.strip_suffix('M'))
	{
		return parse_duration_secs(rest, 60, "m", now_epoch);
	}
	if let Some(rest) = trimmed
		.strip_suffix('s')
		.or_else(|| trimmed.strip_suffix('S'))
	{
		return parse_duration_secs(rest, 1, "s", now_epoch);
	}
	parse_rfc3339(trimmed).map(Some)
}

fn parse_duration_secs(
	digits: &str,
	unit_secs: u64,
	unit_label: &str,
	now_epoch: u64,
) -> Result<Option<u64>, String> {
	let amount: u64 = digits
		.parse()
		.map_err(|_| format!("duration {digits}{unit_label} is not a number"))?;
	Ok(Some(
		now_epoch.saturating_sub(amount.saturating_mul(unit_secs)),
	))
}

/// Hand-rolled RFC 3339 parser: `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]`.
/// Avoids the `time` crate's `parsing` feature (a new feature flag would
/// mean a Cargo.toml change, and the existing `time` usage in this
/// codebase is `time::unix_now` only). The output is always UTC: an
/// explicit `+HH:MM` offset is subtracted from the wall-clock fields, so
/// a value like `2024-01-02T03:04:05+02:00` becomes `01:04:05 UTC`.
pub(crate) fn parse_rfc3339(value: &str) -> Result<u64, String> {
	let (date, rest) = value
		.split_once('T')
		.ok_or_else(|| format!("since {value:?} is not RFC 3339 (no T separator)"))?;
	let mut date_iter = date.split('-');
	let year: i64 = date_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the year"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric year"))?;
	let month: u64 = date_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the month"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric month"))?;
	let day: u64 = date_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the day"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric day"))?;
	if date_iter.next().is_some() {
		return Err(format!("since {value:?} has too many date parts"));
	}
	// Reject month/day-of-month ranges here. `days_from_civil` accepts any
	// positive day (e.g. 40) and rolls into the next month, but a
	// well-formed RFC 3339 value is a calendar date, not a day-count.
	if !(1..=12).contains(&month) {
		return Err(format!("since {value:?} has a month out of range"));
	}
	if !day::is_calendar_day(year, month, day) {
		return Err(format!("since {value:?} is not a day of the calendar"));
	}
	let (time, offset_seconds) = if let Some(time) = rest.strip_suffix('Z') {
		(time, 0i64)
	} else if let Some((time, offset)) = rest.rsplit_once('+') {
		let secs = parse_offset(offset)?;
		(time, secs)
	} else if let Some((time, offset)) = rest.rsplit_once('-') {
		let secs = parse_offset(offset)?;
		(time, -secs)
	} else {
		(rest, 0i64)
	};
	let mut time_iter = time.split(':');
	let hour: u64 = time_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the hour"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric hour"))?;
	let minute: u64 = time_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the minute"))?
		.parse()
		.map_err(|_| format!("since {value:?} has a non-numeric minute"))?;
	let second_part = time_iter
		.next()
		.ok_or_else(|| format!("since {value:?} is missing the seconds"))?;
	if time_iter.next().is_some() {
		return Err(format!("since {value:?} has too many time parts"));
	}
	let second: u64 = match second_part.split_once('.') {
		Some((whole, _frac)) => whole
			.parse()
			.map_err(|_| format!("since {value:?} has a non-numeric second"))?,
		None => second_part
			.parse()
			.map_err(|_| format!("since {value:?} has a non-numeric second"))?,
	};
	if hour > 23 {
		return Err(format!("since {value:?} has an hour out of range"));
	}
	if minute > 59 {
		return Err(format!("since {value:?} has a minute out of range"));
	}
	if second > 60 {
		// Leap second tolerance: real producers do not emit `:60`, but
		// `2024-01-02T23:59:60Z` has shown up in the wild, and rejecting
		// it would be a surprise. We accept and let the caller see
		// `23:59:60` as the next minute in practice (no further
		// validation).
	}
	let days = days_from_civil(year, month, day);
	let hh: i64 =
		i64::try_from(hour).map_err(|_| format!("since {value:?} has an out-of-range hour"))?;
	let mm: i64 =
		i64::try_from(minute).map_err(|_| format!("since {value:?} has an out-of-range minute"))?;
	let ss: i64 =
		i64::try_from(second).map_err(|_| format!("since {value:?} has an out-of-range second"))?;
	let local: i64 = days
		.checked_mul(86_400)
		.and_then(|v| v.checked_add(hh * 3600 + mm * 60 + ss))
		.ok_or_else(|| format!("since {value:?} is out of range"))?;
	let utc = local - offset_seconds;
	u64::try_from(utc).map_err(|_| format!("since {value:?} is before the epoch"))
}

/// `±HH:MM`, the offset part of an RFC 3339 timestamp. Always positive
/// (the sign is the caller's problem, since the prefix character is
/// also the prefix of a negative year in the date).
fn parse_offset(offset: &str) -> Result<i64, String> {
	let mut iter = offset.split(':');
	let hours: i64 = iter
		.next()
		.ok_or_else(|| format!("since ... {offset:?} is not an offset"))?
		.parse()
		.map_err(|_| format!("since ... {offset:?} has a non-numeric hour"))?;
	let minutes: i64 = match iter.next() {
		Some(minutes) => minutes
			.parse()
			.map_err(|_| format!("since ... {offset:?} has a non-numeric minute"))?,
		None => 0,
	};
	let seconds = hours * 3600 + minutes * 60;
	if !(0..60).contains(&minutes) || !day::is_clock_offset(seconds) {
		return Err(format!("since ... {offset:?} is not a UTC offset"));
	}
	Ok(seconds)
}

#[cfg(test)]
mod tests;
