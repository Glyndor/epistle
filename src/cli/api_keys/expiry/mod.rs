//! How `epistle api-key create` reads an expiry and how `api-key list` and
//! `status` show one. A raw epoch stays valid; a date, an RFC 3339 instant or
//! a duration such as `90d` is read on top of it.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::webdav::rrule::{civil_from_secs, days_from_civil};

const UNITS: &str = "s, m, h, d or w";
const DAY: u64 = 86_400;
/// 2001-09-09, the earliest epoch taken at face value. A bare number below
/// it is far more likely a year (`2027`) or a compact date (`20270131`).
const FIRST_EPOCH: u64 = 1_000_000_000;

/// The current time as epoch seconds; a clock before 1970 reads as zero.
pub(in crate::cli) fn now_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs())
}

/// `--expires-at`: an epoch, a date, an RFC 3339 instant or a duration.
pub(in crate::cli) fn parse_expires_at(value: &str) -> Result<u64, String> {
	at(value, now_secs())
}

/// `--expires-in`: a duration with a unit, counted from now.
pub(super) fn parse_expires_in(value: &str) -> Result<u64, String> {
	within(value, now_secs())
}

fn at(value: &str, now: u64) -> Result<u64, String> {
	let value = value.trim();
	if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
		return value
			.parse()
			.ok()
			.filter(|epoch| (FIRST_EPOCH..=crate::clock::LAST_INSTANT).contains(epoch))
			.ok_or_else(|| {
				format!(
					"\"{value}\" is not a plausible Unix epoch in seconds; \
					 use a date such as 2027-01-31 or a duration such as 90d"
				)
			});
	}
	if value.starts_with(|c: char| c.is_ascii_digit()) && value.contains('-') {
		let instant = instant(value).ok_or_else(|| {
			format!(
				"\"{value}\" is not a date: use YYYY-MM-DD, an RFC 3339 instant, \
				 a duration such as 90d or an epoch"
			)
		})?;
		return match u64::try_from(instant) {
			Ok(instant) if instant > now => Ok(instant),
			_ => Err(format!("\"{value}\" is already in the past")),
		};
	}
	within(value, now)
}

fn within(value: &str, now: u64) -> Result<u64, String> {
	let value = value.trim();
	let split = value
		.find(|c: char| !c.is_ascii_digit())
		.filter(|&split| split > 0)
		.ok_or_else(|| {
			format!("\"{value}\" needs a number and a unit ({UNITS}), for example 90d")
		})?;
	let (digits, unit) = value.split_at(split);
	let unit: u64 = match unit {
		"s" => 1,
		"m" => 60,
		"h" => 3600,
		"d" => DAY,
		"w" => 7 * DAY,
		_ => {
			return Err(format!(
				"unknown unit \"{unit}\" in \"{value}\" (use {UNITS})"
			));
		}
	};
	let span = digits
		.parse::<u64>()
		.ok()
		.and_then(|count| count.checked_mul(unit))
		.filter(|&span| span > 0)
		.ok_or_else(|| format!("\"{value}\" is not a usable duration"))?;
	now.checked_add(span)
		.filter(|&instant| instant <= crate::clock::LAST_INSTANT)
		.ok_or_else(|| format!("\"{value}\" is too far away (the last date is 9999-12-31)"))
}

/// `YYYY-MM-DD` (midnight UTC) or `YYYY-MM-DDTHH:MM:SS[.f](Z|+HH:MM)`.
fn instant(value: &str) -> Option<i64> {
	let (date, rest) = match value.split_once(['T', 't']) {
		Some((date, rest)) => (date, Some(rest)),
		None => (value, None),
	};
	let mut parts = date.split('-');
	let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
	if parts.next().is_some() || year.len() != 4 || month.len() != 2 || day.len() != 2 {
		return None;
	}
	let (year, month, day) = (number(year)?, number(month)?, number(day)?);
	let days = days_from_civil(year, month, day);
	if civil_from_secs(days * 86_400) != (year, month, day) {
		return None;
	}
	let seconds = match rest {
		None => 0,
		Some(rest) => time_of_day(rest)?,
	};
	Some(days * 86_400 + seconds)
}

/// `HH:MM:SS[.f]` (a leap second, `:60`, counts as the next minute) plus a mandatory zone, as seconds since the date's midnight
/// UTC.
fn time_of_day(text: &str) -> Option<i64> {
	let zone = text.find(['Z', 'z', '+', '-'])?;
	let (clock, zone) = text.split_at(zone);
	let clock = clock.split_once('.').map_or(clock, |(whole, fraction)| {
		if fraction.bytes().all(|b| b.is_ascii_digit()) && !fraction.is_empty() {
			whole
		} else {
			""
		}
	});
	let mut parts = clock.split(':');
	let (hour, minute, second) = (parts.next()?, parts.next()?, parts.next()?);
	if parts.next().is_some() || [hour, minute, second].iter().any(|p| p.len() != 2) {
		return None;
	}
	let (hour, minute, second) = (number(hour)?, number(minute)?, number(second)?);
	if hour > 23 || minute > 59 || second > 60 {
		return None;
	}
	let offset = if zone.eq_ignore_ascii_case("z") {
		0
	} else {
		let sign = if zone.starts_with('-') { -1 } else { 1 };
		let (zh, zm) = zone[1..].split_once(':')?;
		if zh.len() != 2 || zm.len() != 2 {
			return None;
		}
		let (zh, zm) = (number(zh)?, number(zm)?);
		if zh > 23 || zm > 59 {
			return None;
		}
		sign * (zh * 3600 + zm * 60)
	};
	Some(hour * 3600 + minute * 60 + second - offset)
}

fn number(text: &str) -> Option<i64> {
	if text.bytes().all(|byte| byte.is_ascii_digit()) {
		text.parse().ok()
	} else {
		None
	}
}

/// An instant as RFC 3339, or the bare number when it is past 9999-12-31
/// (an old key written by hand), which no date format can show.
fn readable(epoch: u64) -> String {
	crate::clock::rfc3339_or_epoch(epoch)
}

/// The expiry as `api-key list` prints it: an RFC 3339 instant, marked once
/// it has passed.
pub(super) fn describe(expires_at: u64, now: u64) -> String {
	let when = readable(expires_at);
	if expires_at <= now {
		format!("{when} (expired)")
	} else {
		when
	}
}

/// How long before an expiry `status` starts to warn.
pub(crate) const WARN_WITHIN: u64 = 14 * DAY;

/// The `status` warning for a key that has expired or will within
/// [`WARN_WITHIN`]; `None` for a key that is fine.
pub(crate) fn status_warning(expires_at: u64, now: u64) -> Option<String> {
	let when = readable(expires_at);
	if expires_at <= now {
		return Some(format!("expired on {when}"));
	}
	let left = expires_at - now;
	if left >= WARN_WITHIN {
		return None;
	}
	let days = left.div_ceil(DAY);
	let plural = if days == 1 { "" } else { "s" };
	Some(format!("expires in {days} day{plural}, on {when}"))
}

#[cfg(test)]
mod tests;
