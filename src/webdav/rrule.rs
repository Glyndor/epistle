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
//! - `FREQ=DAILY|WEEKLY|MONTHLY|YEARLY`: the four calendar-stride frequencies.
//! - `INTERVAL=<n>`: stride between occurrences (default `1`).
//! - `COUNT=<n>`: stop after `n` occurrences total (counted from `DTSTART`).
//! - `UNTIL=<datetime>`: stop at an inclusive UTC bound.
//! - `BYDAY` (with an ordinal in a month, `2TU`, `-1FR`), `BYMONTHDAY`
//!   (negative counts from the end), `BYMONTH` and `WKST`, evaluated as
//!   RFC 5545 §3.3.10 describes (`rrule_select.rs`).
//! - A series that starts on the 29th to the 31st recurs only in the months
//!   that have the day.
//!
//! Not evaluated: `BYSETPOS`, `BYWEEKNO`, `BYYEARDAY`, time parts of a rule,
//! `YEARLY` with `BYDAY` and no `BYMONTH`, and frequencies finer than a day.
//! [`parse_rule`] flags such a rule ([`Rule::unsupported`]) so a caller that
//! must not read busy time as free can refuse it; an unflagged-unaware caller
//! gets the rule without those parts. `EXDATE` is ignored (an excluded
//! occurrence still counts as busy, the safe side); `RDATE` is read by the
//! free-busy scan, not here. Local and floating times are read as UTC.
//! A non-recurring event yields its single `DTSTART` when it lands in the
//! window.

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
	/// `BYDAY`: weekdays, each with an optional ordinal (`2TU`, `-1FR`).
	pub by_day: Vec<ByDay>,
	/// `BYMONTHDAY`: days of the month; negative counts from the end.
	pub by_month_day: Vec<i32>,
	/// `BYMONTH`: months, 1 to 12.
	pub by_month: Vec<u32>,
	/// `WKST`: the first day of the week, `0` Monday to `6` Sunday.
	pub wkst: u32,
	/// The rule has a part, a value or a combination that [`expand_bounded`]
	/// does not evaluate (`BYSETPOS`, `BYWEEKNO`, `BYYEARDAY`, a time part,
	/// an ordinal without a month, and so on).
	pub unsupported: bool,
}

/// One `BYDAY` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByDay {
	/// `2` for `2TU`, `-1` for `-1FR`; `None` for every such weekday.
	pub ordinal: Option<i32>,
	/// `0` Monday to `6` Sunday.
	pub weekday: u32,
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
/// is present. A part this module does not evaluate sets
/// [`Rule::unsupported`].
pub fn parse_rule(value: &str) -> Option<Rule> {
	let mut freq = None;
	let mut rule = Rule {
		freq: Freq::Daily,
		interval: 1,
		count: None,
		until: None,
		by_day: Vec::new(),
		by_month_day: Vec::new(),
		by_month: Vec::new(),
		wkst: 0,
		unsupported: false,
	};
	for part in value.trim().split(';') {
		let (key, val) = part.split_once('=')?;
		let val = val.trim();
		match key.trim().to_ascii_uppercase().as_str() {
			"FREQ" => {
				freq = match val.to_ascii_uppercase().as_str() {
					"DAILY" => Some(Freq::Daily),
					"WEEKLY" => Some(Freq::Weekly),
					"MONTHLY" => Some(Freq::Monthly),
					"YEARLY" => Some(Freq::Yearly),
					_ => return None,
				};
			}
			"INTERVAL" => rule.interval = val.parse().ok().filter(|n| *n >= 1).unwrap_or(1),
			"COUNT" => rule.count = val.parse().ok(),
			"UNTIL" => rule.until = parse_datetime(val),
			"BYDAY" => match val.split(',').map(parse_by_day).collect::<Option<Vec<_>>>() {
				Some(days) => rule.by_day = days,
				None => rule.unsupported = true,
			},
			"BYMONTHDAY" => match val.split(',').map(parse_signed).collect::<Option<Vec<_>>>() {
				Some(days) if days.iter().all(|d| (1..=31).contains(&d.abs())) => {
					rule.by_month_day = days;
				}
				_ => rule.unsupported = true,
			},
			"BYMONTH" => match val
				.split(',')
				.map(|m| m.trim().parse::<u32>().ok())
				.collect::<Option<Vec<_>>>()
			{
				Some(months) if months.iter().all(|m| (1..=12).contains(m)) => {
					rule.by_month = months
				}
				_ => rule.unsupported = true,
			},
			"WKST" => match weekday_of(val) {
				Some(day) => rule.wkst = day,
				None => rule.unsupported = true,
			},
			_ => rule.unsupported = true,
		}
	}
	rule.freq = freq?;
	let ordinals = rule.by_day.iter().any(|d| d.ordinal.is_some());
	rule.unsupported |= match rule.freq {
		Freq::Daily => ordinals,
		Freq::Weekly => ordinals || !rule.by_month_day.is_empty(),
		Freq::Monthly => false,
		Freq::Yearly => {
			!rule.by_day.is_empty() && rule.by_month.is_empty()
				|| ordinals && rule.by_month.is_empty()
		}
	};
	Some(rule)
}

fn weekday_of(code: &str) -> Option<u32> {
	["MO", "TU", "WE", "TH", "FR", "SA", "SU"]
		.iter()
		.position(|name| name.eq_ignore_ascii_case(code.trim()))
		.map(|index| index as u32)
}

fn parse_signed(text: &str) -> Option<i32> {
	let text = text.trim();
	text.strip_prefix('+').unwrap_or(text).parse().ok()
}

fn parse_by_day(entry: &str) -> Option<ByDay> {
	let entry = entry.trim();
	let split = entry.len().checked_sub(2)?;
	let weekday = weekday_of(entry.get(split..)?)?;
	let ordinal = match entry.get(..split)? {
		"" => None,
		text => Some(parse_signed(text).filter(|n| *n != 0 && n.abs() <= 53)?),
	};
	Some(ByDay { ordinal, weekday })
}

/// Whether `value` (an `RRULE` value) is entirely evaluated by
/// [`expand_bounded`]. A caller that must not read busy time as free refuses
/// a rule for which this is false.
pub fn fully_supported(value: &str) -> bool {
	parse_rule(value).is_some_and(|rule| !rule.unsupported)
}

/// The `UNTIL` of an `RRULE` value, when it has a readable one.
pub fn until_of(value: &str) -> Option<i64> {
	value.split(';').find_map(|part| {
		let (key, val) = part.split_once('=')?;
		key.trim()
			.eq_ignore_ascii_case("UNTIL")
			.then(|| parse_datetime(val.trim()))
			.flatten()
	})
}

/// The `n`-th occurrence start (epoch seconds) of a recurrence, counting from
/// `dtstart` as occurrence `0`.
///
/// Day/week strides are plain arithmetic off `dtstart`. Month/year strides are
/// anchored on `dtstart`'s day-of-month and time-of-day. A start on the 29th to
/// the 31st never gets here (`expand_bounded` hands it to the day-selecting
/// expansion, which skips the months without the day); the clamp below is for
/// the months that do have it.
fn occurrence_at(dtstart: i64, freq: Freq, interval: u32, n: u32) -> i64 {
	let step = i64::from(interval).saturating_mul(i64::from(n));
	match freq {
		Freq::Daily => dtstart.saturating_add(step.saturating_mul(DAY)),
		Freq::Weekly => dtstart.saturating_add(step.saturating_mul(7 * DAY)),
		Freq::Monthly | Freq::Yearly => {
			// Far beyond any date a request can name: past every window.
			if step > FAR_STEP {
				return i64::MAX;
			}
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

/// The largest month or year stride [`occurrence_at`] computes exactly.
const FAR_STEP: i64 = 200_000_000;

/// An index from which every earlier occurrence starts before `window_start`,
/// so expansion can begin there instead of at `0`. It may be a little lower
/// than the first occurrence in the window, never higher.
fn first_index(dtstart: i64, freq: Freq, interval: u32, window_start: i64) -> u32 {
	let behind = window_start.saturating_sub(dtstart);
	if behind <= 0 {
		return 0;
	}
	let interval = i64::from(interval.max(1));
	let strides = match freq {
		Freq::Daily => behind / (interval * DAY),
		Freq::Weekly => behind / (interval * 7 * DAY),
		Freq::Monthly | Freq::Yearly => {
			let (y0, m0, _) = civil_from_secs(dtstart);
			let (y1, m1, _) = civil_from_secs(window_start);
			let months = (y1 - y0) * 12 + (m1 - m0);
			let calendar_strides = if matches!(freq, Freq::Yearly) {
				months / 12
			} else {
				months
			};
			calendar_strides / interval
		}
	};
	u32::try_from(strides.saturating_sub(1).max(0)).unwrap_or(u32::MAX)
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
/// falls within `[window_start, window_end)`; see [`expand_bounded`]. An
/// expansion that outgrows [`DEFAULT_BUDGET`] is cut short.
pub fn expand(dtstart: i64, rule: Option<&Rule>, window_start: i64, window_end: i64) -> Vec<i64> {
	expand_bounded(dtstart, rule, window_start, window_end, DEFAULT_BUDGET).0
}

/// The most steps (periods walked plus occurrences produced) [`expand`] takes.
pub const DEFAULT_BUDGET: usize = 100_000;

/// Expand a `VEVENT` into the occurrences within `[window_start, window_end)`,
/// taking at most `budget` steps. The flag is `true` when the budget ran out
/// before the expansion finished, so the occurrences are only the ones found.
///
/// `dtstart` is the event's first start (epoch seconds). `rule` is the parsed
/// `RRULE`, or `None` for a non-recurring event (which yields its single
/// `dtstart` when in window). Expansion ends at the window end, at `COUNT`
/// and at `UNTIL`. Without `COUNT`, the periods that end before the window are
/// skipped arithmetically, not walked one by one. A rule with `BYDAY`,
/// `BYMONTHDAY` or `BYMONTH` selects its days as RFC 5545 §3.3.10 describes;
/// a rule flagged [`Rule::unsupported`] is expanded as if those parts were
/// absent, so a caller that cannot afford that checks the flag first.
pub fn expand_bounded(
	dtstart: i64,
	rule: Option<&Rule>,
	window_start: i64,
	window_end: i64,
	budget: usize,
) -> (Vec<i64>, bool) {
	let mut out = Vec::new();
	let Some(rule) = rule else {
		if dtstart >= window_start && dtstart < window_end {
			out.push(dtstart);
		}
		return (out, false);
	};
	let (_, month, day) = civil_from_secs(dtstart);
	// A start on the 29th to the 31st recurs only in the months that have the
	// day (RFC 5545 §3.3.10), which only the day-selecting expansion does.
	let skips_months = match rule.freq {
		Freq::Monthly => day > 28,
		Freq::Yearly => month == 2 && day == 29,
		Freq::Daily | Freq::Weekly => false,
	};
	if skips_months
		|| !rule.by_day.is_empty()
		|| !rule.by_month_day.is_empty()
		|| !rule.by_month.is_empty()
	{
		return select::expand(dtstart, rule, window_start, window_end, budget);
	}
	let first = first_index(dtstart, rule.freq, rule.interval, window_start);
	let mut left = budget;
	for n in first.. {
		if left == 0 {
			return (out, true);
		}
		left -= 1;
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
	(out, false)
}

#[path = "rrule_select.rs"]
mod select;

#[cfg(test)]
#[path = "rrule_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "rrule_select_tests.rs"]
mod select_tests;
