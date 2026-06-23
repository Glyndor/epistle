//! A minimal iCalendar recurrence (RFC 5545 §3.8.5) expander, self-contained.
//!
//! CalDAV's `free-busy-query` must enumerate the concrete instances of a
//! recurring `VEVENT` inside a requested UTC window. This module does exactly
//! that — and nothing more — with no calendar dependency: it parses an
//! iCalendar UTC datetime (`YYYYMMDDTHHMMSSZ`) to epoch seconds with a
//! hand-rolled days-from-civil routine, and walks a `RRULE` forward from
//! `DTSTART`, yielding every occurrence start that falls in `[start, end)`.
//!
//! # Supported subset
//!
//! - `FREQ=DAILY|WEEKLY|MONTHLY|YEARLY` — the four calendar-stride frequencies.
//! - `INTERVAL=<n>` — stride between occurrences (default `1`).
//! - `COUNT=<n>` — stop after `n` occurrences total (counted from `DTSTART`).
//! - `UNTIL=<datetime>` — stop at an inclusive UTC bound.
//!
//! Deliberately **out of scope** (a documented simplification): `BYDAY`,
//! `BYMONTH`, `BYMONTHDAY`, `BYSETPOS`, `WKST`, `EXDATE`, `RDATE`,
//! secondly/minutely/hourly frequencies, and local/floating times. An event
//! with an unsupported `FREQ` yields no occurrences; a non-recurring event
//! yields its single `DTSTART` when it lands in the window.

/// Seconds in a day.
const DAY: i64 = 86_400;

/// A recurrence frequency we can expand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freq {
	/// `FREQ=DAILY`.
	Daily,
	/// `FREQ=WEEKLY`.
	Weekly,
	/// `FREQ=MONTHLY`.
	Monthly,
	/// `FREQ=YEARLY`.
	Yearly,
}

/// A parsed `RRULE`, reduced to the supported subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
	/// The recurrence frequency.
	pub freq: Freq,
	/// The interval between occurrences (>= 1).
	pub interval: u32,
	/// An optional total occurrence count.
	pub count: Option<u32>,
	/// An optional inclusive UTC end bound, as epoch seconds.
	pub until: Option<i64>,
}

/// Parse an iCalendar UTC datetime `YYYYMMDDTHHMMSSZ` (or a date-only
/// `YYYYMMDD`, treated as midnight UTC) into epoch seconds. Returns `None` for
/// any malformed input — fail closed, never guess a time.
pub fn parse_datetime(value: &str) -> Option<i64> {
	let value = value.trim();
	let bytes = value.as_bytes();
	if bytes.len() < 8 {
		return None;
	}
	let year: i64 = value.get(0..4)?.parse().ok()?;
	let month: i64 = value.get(4..6)?.parse().ok()?;
	let day: i64 = value.get(6..8)?.parse().ok()?;
	if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
		return None;
	}
	let days = days_from_civil(year, month, day);
	let mut secs = days * DAY;
	if bytes.len() >= 15 && bytes[8] == b'T' {
		let hour: i64 = value.get(9..11)?.parse().ok()?;
		let minute: i64 = value.get(11..13)?.parse().ok()?;
		let second: i64 = value.get(13..15)?.parse().ok()?;
		if hour > 23 || minute > 59 || second > 60 {
			return None;
		}
		secs += hour * 3600 + minute * 60 + second;
	}
	Some(secs)
}

/// Days since the Unix epoch (1970-01-01) for a civil date, via Howard
/// Hinnant's `days_from_civil` algorithm. Valid for any Gregorian date;
/// negative for dates before the epoch.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
	let y = if month <= 2 { year - 1 } else { year };
	let era = if y >= 0 { y } else { y - 399 } / 400;
	let yoe = y - era * 400;
	let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	era * 146_097 + doe - 719_468
}

/// Convert epoch seconds back to a civil `(year, month, day)` at UTC midnight
/// of that instant. The inverse of [`days_from_civil`] for the date part.
pub fn civil_from_secs(secs: i64) -> (i64, i64, i64) {
	let days = secs.div_euclid(DAY);
	let z = days + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let year = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = doy - (153 * mp + 2) / 5 + 1;
	let month = if mp < 10 { mp + 3 } else { mp - 9 };
	(if month <= 2 { year + 1 } else { year }, month, day)
}

/// Parse an `RRULE` value (the part after `RRULE:`), e.g.
/// `FREQ=WEEKLY;INTERVAL=2;COUNT=10`. Returns `None` if no recognised `FREQ`
/// is present. Unknown parts are ignored (forward-compatible).
pub fn parse_rule(value: &str) -> Option<Rule> {
	let mut freq = None;
	let mut interval = 1u32;
	let mut count = None;
	let mut until = None;
	for part in value.trim().split(';') {
		let (key, val) = part.split_once('=')?;
		match key.trim().to_ascii_uppercase().as_str() {
			"FREQ" => {
				freq = match val.trim().to_ascii_uppercase().as_str() {
					"DAILY" => Some(Freq::Daily),
					"WEEKLY" => Some(Freq::Weekly),
					"MONTHLY" => Some(Freq::Monthly),
					"YEARLY" => Some(Freq::Yearly),
					_ => return None,
				};
			}
			"INTERVAL" => interval = val.trim().parse().ok().filter(|n| *n >= 1).unwrap_or(1),
			"COUNT" => count = val.trim().parse().ok(),
			"UNTIL" => until = parse_datetime(val.trim()),
			_ => {}
		}
	}
	freq.map(|freq| Rule {
		freq,
		interval,
		count,
		until,
	})
}

/// The `n`-th occurrence start (epoch seconds) of a recurrence, counting from
/// `dtstart` as occurrence `0`.
///
/// Day/week strides are plain arithmetic off `dtstart`. Month/year strides are
/// anchored on `dtstart`'s day-of-month and time-of-day — never on the previous
/// (possibly clamped) occurrence — so a Jan 31 monthly series is Jan 31, Feb 28,
/// Mar 31, … rather than collapsing to the 28th. The day is clamped into each
/// target month.
fn occurrence_at(dtstart: i64, freq: Freq, interval: u32, n: u32) -> i64 {
	let step = interval as i64 * n as i64;
	match freq {
		Freq::Daily => dtstart + step * DAY,
		Freq::Weekly => dtstart + step * 7 * DAY,
		Freq::Monthly | Freq::Yearly => {
			let (year, month, day) = civil_from_secs(dtstart);
			let time = dtstart.rem_euclid(DAY);
			let (y, m) = if matches!(freq, Freq::Yearly) {
				(year + step, month)
			} else {
				let total = (month - 1) + step;
				(year + total.div_euclid(12), total.rem_euclid(12) + 1)
			};
			let clamped = day.min(days_in_month(y, m));
			days_from_civil(y, m, clamped) * DAY + time
		}
	}
}

/// The number of days in a given civil month, accounting for leap years.
fn days_in_month(year: i64, month: i64) -> i64 {
	match month {
		1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
		4 | 6 | 9 | 11 => 30,
		2 if is_leap(year) => 29,
		2 => 28,
		_ => 30,
	}
}

/// Whether `year` is a Gregorian leap year.
fn is_leap(year: i64) -> bool {
	(year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Expand a `VEVENT` into the epoch-second start times of every occurrence that
/// falls within `[window_start, window_end)`.
///
/// `dtstart` is the event's first start (epoch seconds). `rule` is the parsed
/// `RRULE`, or `None` for a non-recurring event (which yields its single
/// `dtstart` when in window). Expansion is bounded three ways so it always
/// terminates: by the window end, by `COUNT`, and by `UNTIL`; a hard cap guards
/// against a pathological window.
pub fn expand(dtstart: i64, rule: Option<&Rule>, window_start: i64, window_end: i64) -> Vec<i64> {
	let mut out = Vec::new();
	let Some(rule) = rule else {
		if dtstart >= window_start && dtstart < window_end {
			out.push(dtstart);
		}
		return out;
	};
	// A safety cap: no expansion considers more than this many occurrences,
	// regardless of the window — a recurring event in a huge window cannot be
	// turned into an unbounded allocation. Occurrences are monotonically
	// increasing, so once one lands at or past the window end we can stop.
	const MAX: u32 = 100_000;
	for n in 0..MAX {
		if let Some(count) = rule.count
			&& n >= count
		{
			break;
		}
		let current = occurrence_at(dtstart, rule.freq, rule.interval, n);
		if let Some(until) = rule.until
			&& current > until
		{
			break;
		}
		if current >= window_end {
			break;
		}
		if current >= window_start {
			out.push(current);
		}
	}
	out
}

#[cfg(test)]
#[path = "rrule_tests.rs"]
mod tests;
