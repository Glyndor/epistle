//! RFC 5322 date parsing for the Sieve `date` test (RFC 5260).

/// Extract a date-part (`year`, `month`, `day`, `hour`, `minute`, `second`,
/// `date`, `time`) from an RFC 5322 date header value, or `None` if the value
/// cannot be parsed or the part is unsupported.
pub(super) fn extract_part(header_value: &str, part: &str) -> Option<String> {
	let (year, month, day, hour, minute, second) = parse(header_value)?;
	format_part(year, month, day, hour, minute, second, part)
}

/// Extract a date-part from a Unix timestamp in UTC (Sieve `currentdate`).
pub(super) fn extract_part_from_unix(now: u64, part: &str) -> Option<String> {
	let (year, month, day, hour, minute, second) = civil_from_unix(now);
	format_part(year, month, day, hour, minute, second, part)
}

/// Render the requested date-part from numeric components.
fn format_part(
	year: u32,
	month: u32,
	day: u32,
	hour: u32,
	minute: u32,
	second: u32,
	part: &str,
) -> Option<String> {
	Some(match part.to_ascii_lowercase().as_str() {
		"year" => format!("{year:04}"),
		"month" => format!("{month:02}"),
		"day" => format!("{day:02}"),
		"hour" => format!("{hour:02}"),
		"minute" => format!("{minute:02}"),
		"second" => format!("{second:02}"),
		"date" => format!("{year:04}-{month:02}-{day:02}"),
		"time" => format!("{hour:02}:{minute:02}:{second:02}"),
		_ => return None,
	})
}

/// Civil date (UTC) from a Unix timestamp (Howard Hinnant's algorithm).
fn civil_from_unix(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
	let days = (secs / 86_400) as i64;
	let sod = secs % 86_400;
	let (hour, minute, second) = (
		(sod / 3600) as u32,
		((sod % 3600) / 60) as u32,
		(sod % 60) as u32,
	);
	let z = days + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
	let year = (yoe + era * 400 + i64::from(month <= 2)) as u32;
	(year, month, day, hour, minute, second)
}

/// Parse `[Day, ]D Mon YYYY HH:MM:SS [zone]` into its numeric components.
fn parse(value: &str) -> Option<(u32, u32, u32, u32, u32, u32)> {
	let mut tokens = value.split_whitespace().peekable();
	// Skip an optional `Day,` day-of-week prefix.
	if tokens.peek().is_some_and(|t| t.ends_with(',')) {
		tokens.next();
	}
	let day: u32 = tokens.next()?.parse().ok()?;
	let month = month_number(tokens.next()?)?;
	let year: u32 = tokens.next()?.parse().ok()?;
	let mut time = tokens.next()?.split(':');
	let hour: u32 = time.next()?.parse().ok()?;
	let minute: u32 = time.next()?.parse().ok()?;
	let second: u32 = time.next().unwrap_or("0").parse().ok()?;
	(day <= 31 && month <= 12 && hour < 24 && minute < 60 && second < 61)
		.then_some((year, month, day, hour, minute, second))
}

fn month_number(name: &str) -> Option<u32> {
	const MONTHS: [&str; 12] = [
		"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
	];
	let key = name.get(..3)?.to_ascii_lowercase();
	MONTHS.iter().position(|m| *m == key).map(|i| i as u32 + 1)
}

#[cfg(test)]
mod tests {
	use super::*;

	const DATE: &str = "Wed, 17 Jun 2026 14:30:05 +0000";

	#[test]
	fn extracts_each_part() {
		assert_eq!(extract_part(DATE, "year").as_deref(), Some("2026"));
		assert_eq!(extract_part(DATE, "month").as_deref(), Some("06"));
		assert_eq!(extract_part(DATE, "day").as_deref(), Some("17"));
		assert_eq!(extract_part(DATE, "hour").as_deref(), Some("14"));
		assert_eq!(extract_part(DATE, "minute").as_deref(), Some("30"));
		assert_eq!(extract_part(DATE, "second").as_deref(), Some("05"));
		assert_eq!(extract_part(DATE, "date").as_deref(), Some("2026-06-17"));
		assert_eq!(extract_part(DATE, "time").as_deref(), Some("14:30:05"));
	}

	#[test]
	fn handles_missing_weekday_and_seconds() {
		assert_eq!(
			extract_part("1 Jan 2000 00:00", "date").as_deref(),
			Some("2000-01-01")
		);
	}

	#[test]
	fn rejects_garbage_and_unknown_parts() {
		assert!(extract_part("not a date", "year").is_none());
		assert!(extract_part(DATE, "weekday").is_none());
	}

	#[test]
	fn unix_components_match_known_timestamp() {
		// 1781724605 = 2026-06-17 19:30:05 UTC.
		let ts = 1_781_724_605;
		assert_eq!(
			extract_part_from_unix(ts, "date").as_deref(),
			Some("2026-06-17")
		);
		assert_eq!(
			extract_part_from_unix(ts, "time").as_deref(),
			Some("19:30:05")
		);
		assert_eq!(extract_part_from_unix(ts, "year").as_deref(), Some("2026"));
		// Epoch.
		assert_eq!(
			extract_part_from_unix(0, "date").as_deref(),
			Some("1970-01-01")
		);
	}
}
