//! Free-busy text helpers: the requested range, XML attributes and the VFREEBUSY object.

use super::*;

/// Extract the `start`/`end` of a CalDAV `<C:time-range start=... end=.../>` (a
/// free-busy-query). Both are iCalendar UTC datetimes; either may be missing.
/// Returns `None` if neither bound parses.
pub(super) fn time_range(body: &str) -> Option<Period> {
	let start = attr(body, "start").and_then(|v| rrule::parse_datetime(&v));
	let end = attr(body, "end").and_then(|v| rrule::parse_datetime(&v));
	match (start, end) {
		(Some(s), Some(e)) if e > s => Some((s, e)),
		_ => None,
	}
}

/// Extract the value of an XML attribute `name="value"` from `body` — a tiny
/// scan good enough for the single `time-range` element. Single or double
/// quotes are accepted.
fn attr(body: &str, name: &str) -> Option<String> {
	let needle = format!("{name}=");
	let mut from = 0;
	while let Some(rel) = body[from..].find(&needle) {
		let at = from + rel;
		// Ensure this is a whole attribute name, not a suffix of another.
		let before_ok = at == 0 || !body.as_bytes()[at - 1].is_ascii_alphanumeric();
		let rest = &body[at + needle.len()..];
		if before_ok {
			let quote = rest.chars().next()?;
			if quote == '"' || quote == '\'' {
				let value = &rest[1..];
				if let Some(close) = value.find(quote) {
					return Some(value[..close].to_string());
				}
			}
		}
		from = at + needle.len();
	}
	None
}

/// Extract the free-busy range from an iTIP `VFREEBUSY` request body (the Outbox
/// POST): its `DTSTART`/`DTEND` lines. Returns `None` if the range is absent.
pub(super) fn itip_range(ics: &str) -> Option<Period> {
	let unfolded = unfold(ics);
	let mut start = None;
	let mut end = None;
	for line in unfolded.lines() {
		let line = line.trim_end_matches('\r');
		let Some((name_and_params, value)) = line.split_once(':') else {
			continue;
		};
		let name = name_and_params
			.split(';')
			.next()
			.unwrap_or("")
			.to_ascii_uppercase();
		match name.as_str() {
			"DTSTART" => start = rrule::parse_datetime(value),
			"DTEND" => end = rrule::parse_datetime(value),
			_ => {}
		}
	}
	match (start, end) {
		(Some(s), Some(e)) if e > s => Some((s, e)),
		_ => None,
	}
}

/// Format epoch seconds as an iCalendar UTC datetime `YYYYMMDDTHHMMSSZ`.
fn format_datetime(secs: i64) -> String {
	let (year, month, day) = rrule::civil_from_secs(secs);
	let rem = secs.rem_euclid(86_400);
	let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
	format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// Build a `VFREEBUSY` iCalendar object for `periods` within `[start, end)`.
pub(super) fn vfreebusy(start: i64, end: i64, periods: &[Period]) -> String {
	let mut out = String::from(
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//epistle//CalDAV//EN\r\nBEGIN:VFREEBUSY\r\n",
	);
	out.push_str(&format!("DTSTART:{}\r\n", format_datetime(start)));
	out.push_str(&format!("DTEND:{}\r\n", format_datetime(end)));
	for (busy_start, busy_end) in periods {
		out.push_str(&format!(
			"FREEBUSY;FBTYPE=BUSY:{}/{}\r\n",
			format_datetime(*busy_start),
			format_datetime(*busy_end)
		));
	}
	out.push_str("END:VFREEBUSY\r\nEND:VCALENDAR\r\n");
	out
}
