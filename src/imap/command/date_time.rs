//! The quoted `date-time` of APPEND and REPLACE (RFC 9051 §9):
//! `"dd-Mon-yyyy hh:mm:ss +zzzz"`, where a one-digit day may be padded
//! with a space. It becomes the message's INTERNALDATE, shown in its zone.

use crate::imap::internal_date::{InternalDate, MAX_ZONE};
use std::time::{Duration, UNIX_EPOCH};

const MONTHS: [&str; 12] = [
	"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Split an optional leading quoted date-time off `text`. `Ok((None, text))`
/// when `text` does not start with a quote; `Err(())` when it does but the
/// value is not a valid date-time, which the caller answers with BAD.
pub(super) fn split_date_time(text: &str) -> Result<(Option<InternalDate>, &str), ()> {
	let Some(quoted) = text.strip_prefix('"') else {
		return Ok((None, text));
	};
	let (value, rest) = quoted.split_once('"').ok_or(())?;
	let time = parse(value).ok_or(())?;
	Ok((Some(time), rest.trim_start()))
}

/// Parse the inside of a date-time string into an instant and its zone.
fn parse(value: &str) -> Option<InternalDate> {
	let value = value.strip_prefix(' ').unwrap_or(value);
	let (date, rest) = value.split_once(' ')?;
	let (time, zone) = rest.split_once(' ')?;
	let mut date = date.split('-');
	let (day, month, year) = (date.next()?, date.next()?, date.next()?);
	if date.next().is_some() || !(1..=2).contains(&day.len()) || year.len() != 4 {
		return None;
	}
	let day: i64 = digits(day)?;
	let month = MONTHS
		.iter()
		.position(|name| name.eq_ignore_ascii_case(month))? as i64
		+ 1;
	let year: i64 = digits(year)?;
	if !(1..=days_in_month(year, month)).contains(&day) {
		return None;
	}
	let mut time = time.split(':');
	let (hour, minute, second) = (time.next()?, time.next()?, time.next()?);
	if time.next().is_some() || [hour, minute, second].iter().any(|part| part.len() != 2) {
		return None;
	}
	let (hour, minute, second) = (digits(hour)?, digits(minute)?, digits(second)?);
	if hour > 23 || minute > 59 || second > 60 {
		return None;
	}
	let offset = zone_offset(zone)?;
	let seconds =
		days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
	let time = if seconds >= 0 {
		UNIX_EPOCH + Duration::from_secs(seconds as u64)
	} else {
		UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
	};
	let zone = i16::try_from(offset / 60).ok()?;
	Some(InternalDate { time, zone })
}

/// The `+hhmm` / `-hhmm` zone as seconds east of UTC, at most `+2359`.
fn zone_offset(zone: &str) -> Option<i64> {
	let sign = match zone.as_bytes().first()? {
		b'+' => 1,
		b'-' => -1,
		_ => return None,
	};
	let digits_part = &zone[1..];
	if digits_part.len() != 4 {
		return None;
	}
	let hours: i64 = digits(&digits_part[..2])?;
	let minutes: i64 = digits(&digits_part[2..])?;
	if minutes > 59 || hours * 60 + minutes > i64::from(MAX_ZONE) {
		return None;
	}
	Some(sign * (hours * 3600 + minutes * 60))
}

fn digits(text: &str) -> Option<i64> {
	if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
		return None;
	}
	text.parse().ok()
}

fn days_in_month(year: i64, month: i64) -> i64 {
	match month {
		2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
		2 => 28,
		4 | 6 | 9 | 11 => 30,
		_ => 31,
	}
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
/// Algorithm: https://howardhinnant.github.io/date_algorithms.html
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
	let y = if month <= 2 { year - 1 } else { year };
	let era = y.div_euclid(400);
	let yoe = y - era * 400;
	let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
	use super::{InternalDate, UNIX_EPOCH, split_date_time};

	fn seconds(date: InternalDate) -> u64 {
		date.time
			.duration_since(UNIX_EPOCH)
			.expect("after epoch")
			.as_secs()
	}

	#[test]
	fn the_zone_is_folded_into_the_instant() {
		let (time, rest) = split_date_time("\"22-Feb-2008 23:00:00 +0200\" {5}").expect("valid");
		// 2008-02-22T21:00:00Z.
		assert_eq!(seconds(time.expect("date")), 1_203_714_000);
		assert_eq!(time.expect("date").zone, 120);
		assert_eq!(rest, "{5}");
		let (time, _) = split_date_time("\" 2-feb-2008 01:00:00 -0130\" {5}").expect("valid");
		// 2008-02-02T02:30:00Z.
		assert_eq!(seconds(time.expect("date")), 1_201_919_400);
		assert_eq!(time.expect("date").zone, -90);
	}

	#[test]
	fn no_quote_means_no_date_and_a_bad_date_is_an_error() {
		assert_eq!(split_date_time("{5}"), Ok((None, "{5}")));
		for bad in [
			"\"30-Feb-2008 00:00:00 +0000\" {5}",
			"\"22-Foo-2008 00:00:00 +0000\" {5}",
			"\"22-Feb-2008 24:00:00 +0000\" {5}",
			"\"22-Feb-2008 00:00:00 0000\" {5}",
			"\"22-Feb-2008 00:00:00 +2400\" {5}",
			"\"22-Feb-2008 00:00:00 +0000 {5}",
		] {
			assert!(split_date_time(bad).is_err(), "{bad}");
		}
	}
}
