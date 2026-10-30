//! Small time helpers for the status checks: no calendar dependency, so only
//! the formats the checks meet are parsed.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::webdav::rrule::days_from_civil;

/// Epoch seconds of `time`, clamped to zero before the epoch.
pub(super) fn epoch(time: SystemTime) -> i64 {
	time.duration_since(UNIX_EPOCH)
		.map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
		.unwrap_or(0)
}

/// Parse an RFC 3339 timestamp (`2026-10-09T08:00:00.123456789+02:00`, `Z`
/// accepted) into epoch seconds. Fractions are dropped.
pub(in crate::cli) fn parse_rfc3339(text: &str) -> Option<i64> {
	let text = text.trim();
	let (date, rest) = text.split_once(['T', 't', ' '])?;
	let mut date_parts = date.split('-');
	let year: i64 = date_parts.next()?.parse().ok()?;
	let month: i64 = date_parts.next()?.parse().ok()?;
	let day: i64 = date_parts.next()?.parse().ok()?;
	if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
		return None;
	}
	let zone_at = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
	let (clock, zone) = rest.split_at(zone_at);
	let clock = clock.split('.').next()?;
	let mut clock_parts = clock.split(':');
	let hour: i64 = clock_parts.next()?.parse().ok()?;
	let minute: i64 = clock_parts.next()?.parse().ok()?;
	let second: i64 = clock_parts.next().unwrap_or("0").parse().ok()?;
	if hour > 23 || minute > 59 || second > 60 {
		return None;
	}
	let offset = match zone.as_bytes().first() {
		None | Some(b'Z' | b'z') => 0,
		Some(sign @ (b'+' | b'-')) => {
			let (hours, minutes) = zone[1..].split_once(':')?;
			let seconds = hours.parse::<i64>().ok()? * 3600 + minutes.parse::<i64>().ok()? * 60;
			if *sign == b'-' { -seconds } else { seconds }
		}
		_ => return None,
	};
	Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Parse the timestamp in clamd's `VERSION` reply (`Mon Oct  9 08:00:00 2026`,
/// UTC) into epoch seconds.
pub(super) fn parse_clamd_date(text: &str) -> Option<i64> {
	let mut words = text.split_whitespace();
	let _weekday = words.next()?;
	let month = match words.next()? {
		"Jan" => 1,
		"Feb" => 2,
		"Mar" => 3,
		"Apr" => 4,
		"May" => 5,
		"Jun" => 6,
		"Jul" => 7,
		"Aug" => 8,
		"Sep" => 9,
		"Oct" => 10,
		"Nov" => 11,
		"Dec" => 12,
		_ => return None,
	};
	let day: i64 = words.next()?.parse().ok()?;
	let mut clock = words.next()?.split(':');
	let hour: i64 = clock.next()?.parse().ok()?;
	let minute: i64 = clock.next()?.parse().ok()?;
	let second: i64 = clock.next()?.parse().ok()?;
	let year: i64 = words.next()?.parse().ok()?;
	if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
		return None;
	}
	Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests;
