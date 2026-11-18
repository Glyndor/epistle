//! The VEVENT fields the free-busy scan needs, and iCalendar line unfolding.

use super::*;

/// The fields of a `VEVENT` the free-busy scan needs.
pub(in crate::webdav) struct VEvent {
	/// `DTSTART` as epoch seconds, if parseable.
	pub(in crate::webdav) dtstart: Option<i64>,
	/// `DTEND` as epoch seconds, if present.
	pub(in crate::webdav) dtend: Option<i64>,
	/// The `DURATION` property in seconds, if present and readable.
	pub(in crate::webdav) length: Option<i64>,
	/// `DTSTART` is a date, not a date-time.
	pub(in crate::webdav) all_day: bool,
	/// The `RRULE` value (after `RRULE:`), if present.
	pub(in crate::webdav) rrule: Option<String>,
	/// The instants listed by `RDATE` properties.
	pub(in crate::webdav) rdates: Vec<i64>,
	/// An `RDATE` value was not a date, a date-time or a period.
	pub(in crate::webdav) rdate_unreadable: bool,
}

impl VEvent {
	/// The event duration in seconds (RFC 5545 §3.6.1): `DTEND - DTSTART`,
	/// else `DURATION`, else one day for an all-day start and zero (a
	/// point-in-time busy marker) otherwise.
	pub(in crate::webdav) fn duration(&self) -> i64 {
		match (self.dtstart, self.dtend) {
			(Some(s), Some(e)) => e - s,
			_ => self.length.unwrap_or(if self.all_day { 86_400 } else { 0 }),
		}
	}
}

/// Parse every `VEVENT` block out of an iCalendar object, after unfolding
/// continuation lines (RFC 5545 §3.1). Only `DTSTART`, `DTEND` and `RRULE` are
/// extracted; everything else (including `VALARM`) is ignored here.
pub(in crate::webdav) fn vevents(ics: &str) -> Vec<VEvent> {
	let unfolded = unfold(ics);
	let mut out = Vec::new();
	let mut current: Option<VEvent> = None;
	for line in unfolded.lines() {
		let line = line.trim_end_matches('\r');
		if line.eq_ignore_ascii_case("BEGIN:VEVENT") {
			current = Some(VEvent {
				dtstart: None,
				dtend: None,
				length: None,
				all_day: false,
				rrule: None,
				rdates: Vec::new(),
				rdate_unreadable: false,
			});
		} else if line.eq_ignore_ascii_case("END:VEVENT") {
			if let Some(event) = current.take() {
				out.push(event);
			}
		} else if let Some(event) = current.as_mut() {
			apply_property(event, line);
		}
	}
	out
}

/// Apply one unfolded content line to the in-progress `VEvent`. A property may
/// carry parameters (`DTSTART;TZID=...:value`); we split on the first unquoted
/// `:` and match on the property name before any `;`.
fn apply_property(event: &mut VEvent, line: &str) {
	let Some((name_and_params, value)) = line.split_once(':') else {
		return;
	};
	let name = name_and_params
		.split(';')
		.next()
		.unwrap_or("")
		.to_ascii_uppercase();
	match name.as_str() {
		"DTSTART" => {
			event.dtstart = rrule::parse_datetime(value);
			event.all_day = value.trim().len() == 8
				|| name_and_params
					.split(';')
					.any(|param| param.eq_ignore_ascii_case("VALUE=DATE"));
		}
		"DTEND" => event.dtend = rrule::parse_datetime(value),
		"DURATION" => event.length = super::super::caldav_filter_ical::duration(value),
		"RRULE" => event.rrule = Some(value.trim().to_string()),
		"RDATE" => {
			for item in value.split(',') {
				// A period is `start/end`: its start is the instant.
				let start = item.split('/').next().unwrap_or("");
				match rrule::parse_datetime(start) {
					Some(at) => event.rdates.push(at),
					None => event.rdate_unreadable = true,
				}
			}
		}
		_ => {}
	}
}

/// Unfold iCalendar content lines (RFC 5545 §3.1): a line beginning with a
/// space or tab is a continuation of the previous line. Returns a string with
/// continuations joined.
pub fn unfold(ics: &str) -> String {
	let mut out = String::with_capacity(ics.len());
	for line in ics.split('\n') {
		let line = line.strip_suffix('\r').unwrap_or(line);
		if let Some(rest) = line.strip_prefix(' ').or_else(|| line.strip_prefix('\t')) {
			out.push_str(rest);
		} else {
			if !out.is_empty() {
				out.push('\n');
			}
			out.push_str(line);
		}
	}
	out
}
