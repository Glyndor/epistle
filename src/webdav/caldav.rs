//! CalDAV (RFC 4791) + free-busy + basic scheduling (RFC 6638), layered onto
//! the base WebDAV server exactly as the CardDAV module is.
//!
//! A calendar is a collection holding a [`MARKER`] file; an event is a `.ics`
//! file served as `text/calendar`. On top of that this module adds:
//!
//! - the [`REPORT`](report) method, dispatching on the request body's root
//!   element into `calendar-multiget`, `calendar-query` and `free-busy-query`.
//! - the `calendar-data`/`getetag` `207 Multi-Status` builder.
//! - free-busy: scan every `VEVENT` in the target calendar, expand its `RRULE`
//!   (see [`super::rrule`]) over the requested UTC range, and emit a
//!   `text/calendar` `VFREEBUSY` with one `FREEBUSY` period per busy instance.
//! - the scheduling Outbox `POST` (RFC 6638 §6): a `VFREEBUSY` request returns
//!   the authenticated account's own free/busy across all its calendars.
//!
//! Every href a client names is resolved through [`path::resolve`], so a REPORT
//! or Outbox request can never read another account's events nor escape the
//! account root — the same fail-closed confinement as the rest of the module.
//!
//! # Out of scope (documented simplifications)
//!
//! - `calendar-query` ignores the filter/time-range and returns every event in
//!   the collection — a valid, common simplification.
//! - Delivery-based iTIP (auto-creating invitations in other users' inboxes) is
//!   not implemented; only the Outbox free-busy lookup is. `VALARM`s are stored
//!   and returned verbatim — no server-side alarm delivery.
//! - The supported `RRULE` subset is documented on [`super::rrule`].

use std::path::Path;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::path;
use super::propfind::escape;
use super::rrule;

/// The CalDAV XML namespace.
pub const CALDAV_NS: &str = "urn:ietf:params:xml:ns:caldav";

/// The marker file that flags a collection as a calendar.
pub const MARKER: &str = ".calendar";

/// The `Content-Type` for an iCalendar resource.
pub const CALENDAR_TYPE: &str = "text/calendar";

/// The conventional path segment of an account's scheduling Outbox.
pub const OUTBOX: &str = "outbox";

/// The conventional path segment of an account's scheduling Inbox.
pub const INBOX: &str = "inbox";

/// Whether `dir` is a calendar collection — a directory holding the [`MARKER`].
pub fn is_calendar(dir: &Path) -> bool {
	dir.is_dir() && dir.join(MARKER).is_file()
}

/// Create the [`MARKER`] inside an existing collection directory, flagging it as
/// a calendar. Returns whether the marker is now present.
pub async fn mark_calendar(dir: &Path) -> bool {
	tokio::fs::write(dir.join(MARKER), b"").await.is_ok()
}

/// Whether a request path names an iCalendar resource (a `.ics` file).
pub fn is_ics_path(uri_path: &str) -> bool {
	uri_path.to_ascii_lowercase().ends_with(".ics")
}

/// Whether a `MKCOL` body requests the CalDAV `calendar` resourcetype — i.e. a
/// `<C:calendar/>` element. Distinguishes a calendar MKCOL from an addressbook
/// or a plain collection.
pub fn requests_calendar(body: &str) -> bool {
	body.contains("calendar")
}

/// The three CalDAV REPORTs this server answers.
#[derive(Debug, PartialEq, Eq)]
pub enum ReportKind {
	/// `calendar-multiget`: return the explicitly listed hrefs.
	Multiget,
	/// `calendar-query`: return every event in the target collection.
	Query,
	/// `free-busy-query`: return a `VFREEBUSY` over a time range.
	FreeBusy,
}

/// Detect a CalDAV REPORT's type from its body without a full XML parse: the
/// first recognised report root element wins. Returns `None` for a body that
/// names none of the three.
pub fn report_kind(body: &str) -> Option<ReportKind> {
	let candidates = [
		(body.find("free-busy-query"), ReportKind::FreeBusy),
		(body.find("calendar-multiget"), ReportKind::Multiget),
		(body.find("calendar-query"), ReportKind::Query),
	];
	candidates
		.into_iter()
		.filter_map(|(pos, kind)| pos.map(|p| (p, kind)))
		.min_by_key(|(p, _)| *p)
		.map(|(_, kind)| kind)
}

/// Whether a request body names any CalDAV report — used by the handler to
/// choose the CalDAV report dispatcher over the CardDAV one.
pub fn is_caldav_report(body: &str) -> bool {
	report_kind(body).is_some()
}

/// Handle a CalDAV `REPORT` against `target` (the request-path resource).
///
/// `calendar-multiget` returns each `<D:href>` named in `body`, resolved through
/// `root` (a traversal or cross-account href is silently dropped).
/// `calendar-query` ignores the filter and returns every `.ics` in `target`.
/// `free-busy-query` scans `target`, expands recurrences over the requested
/// range, and returns a `text/calendar` `VFREEBUSY`. A body naming no report is
/// `400`.
pub async fn report(root: &Path, target: &Path, body: &[u8]) -> Response {
	let text = String::from_utf8_lossy(body);
	let Some(kind) = report_kind(&text) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	match kind {
		ReportKind::Multiget => {
			let mut entries = Vec::new();
			for href in hrefs(&text) {
				if let Some(resolved) = path::resolve(root, &href) {
					push_event(&mut entries, &href, &resolved).await;
				}
			}
			multistatus(&entries).into_response()
		}
		ReportKind::Query => {
			let mut entries = Vec::new();
			collect_events(target, &mut entries).await;
			multistatus(&entries).into_response()
		}
		ReportKind::FreeBusy => free_busy_report(target, &text).await,
	}
}

/// Answer a `free-busy-query`: parse the `<C:time-range>` and emit a
/// `text/calendar` `VFREEBUSY` covering the busy instances in `target`. A
/// missing or malformed range is `400`.
async fn free_busy_report(target: &Path, body: &str) -> Response {
	let Some((start, end)) = time_range(body) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	let periods = busy_periods(&[target.to_path_buf()], start, end).await;
	(
		StatusCode::OK,
		[(header::CONTENT_TYPE, CALENDAR_TYPE)],
		vfreebusy(start, end, &periods),
	)
		.into_response()
}

/// Handle a scheduling Outbox `POST` (RFC 6638 §6.1): the body is expected to be
/// an iTIP `VFREEBUSY` request. We return the authenticated account's own
/// free/busy over the requested range, scanning every calendar collection under
/// `account_root`. A request without a parseable range is `400`.
///
/// This is the one scheduling piece wired up because it reuses the free-busy
/// machinery; delivery-based iTIP is out of scope (see the module docs).
pub async fn outbox_post(account_root: &Path, body: &[u8]) -> Response {
	let text = String::from_utf8_lossy(body);
	let (start, end) = match itip_range(&text) {
		Some(range) => range,
		None => return StatusCode::BAD_REQUEST.into_response(),
	};
	let calendars = calendar_dirs(account_root).await;
	let periods = busy_periods(&calendars, start, end).await;
	(
		StatusCode::OK,
		[(header::CONTENT_TYPE, CALENDAR_TYPE)],
		vfreebusy(start, end, &periods),
	)
		.into_response()
}

/// Collect every calendar collection directory beneath `root` (one level of
/// nesting is enough for the conventional `/home/<calendar>/` layout, but we
/// also include `root` itself if it is a calendar). The Outbox free-busy lookup
/// scans them all so it reflects the account's whole schedule.
async fn calendar_dirs(root: &Path) -> Vec<std::path::PathBuf> {
	let mut out = Vec::new();
	if is_calendar(root) {
		out.push(root.to_path_buf());
	}
	if let Ok(mut dir) = tokio::fs::read_dir(root).await {
		while let Ok(Some(child)) = dir.next_entry().await {
			let path = child.path();
			if is_calendar(&path) {
				out.push(path);
			}
		}
	}
	out
}

/// A busy period: `[start, end)` epoch seconds.
type Period = (i64, i64);

/// Scan every `.ics` in each calendar in `calendars`, expand each `VEVENT`'s
/// recurrence over `[start, end)`, and return the busy periods (clamped to the
/// window). Each occurrence contributes `[occurrence, occurrence + duration)`.
async fn busy_periods(calendars: &[std::path::PathBuf], start: i64, end: i64) -> Vec<Period> {
	let mut periods = Vec::new();
	for calendar in calendars {
		let Ok(mut dir) = tokio::fs::read_dir(calendar).await else {
			continue;
		};
		while let Ok(Some(child)) = dir.next_entry().await {
			let name = child.file_name();
			if !is_ics_path(&name.to_string_lossy()) {
				continue;
			}
			if let Ok(data) = tokio::fs::read(child.path()).await {
				let text = String::from_utf8_lossy(&data);
				collect_busy(&text, start, end, &mut periods);
			}
		}
	}
	periods.sort_unstable();
	periods
}

/// Parse the `VEVENT`s in one iCalendar object and append the busy periods their
/// occurrences produce within `[start, end)` to `out`.
fn collect_busy(ics: &str, start: i64, end: i64, out: &mut Vec<Period>) {
	for event in vevents(ics) {
		let Some(dtstart) = event.dtstart else {
			continue;
		};
		let duration = event.duration().max(0);
		let rule = event.rrule.as_deref().and_then(rrule::parse_rule);
		for occ in rrule::expand(dtstart, rule.as_ref(), start, end) {
			let busy_end = (occ + duration).min(end);
			let busy_start = occ.max(start);
			if busy_end > busy_start {
				out.push((busy_start, busy_end));
			}
		}
	}
}

/// The fields of a `VEVENT` the free-busy scan needs.
struct VEvent {
	/// `DTSTART` as epoch seconds, if parseable.
	dtstart: Option<i64>,
	/// `DTEND` as epoch seconds, if present.
	dtend: Option<i64>,
	/// The `RRULE` value (after `RRULE:`), if present.
	rrule: Option<String>,
}

impl VEvent {
	/// The event duration in seconds: `DTEND - DTSTART`, defaulting to zero
	/// (a point-in-time busy marker) when `DTEND` is absent.
	fn duration(&self) -> i64 {
		match (self.dtstart, self.dtend) {
			(Some(s), Some(e)) => e - s,
			_ => 0,
		}
	}
}

/// Parse every `VEVENT` block out of an iCalendar object, after unfolding
/// continuation lines (RFC 5545 §3.1). Only `DTSTART`, `DTEND` and `RRULE` are
/// extracted; everything else (including `VALARM`) is ignored here.
fn vevents(ics: &str) -> Vec<VEvent> {
	let unfolded = unfold(ics);
	let mut out = Vec::new();
	let mut current: Option<VEvent> = None;
	for line in unfolded.lines() {
		let line = line.trim_end_matches('\r');
		if line.eq_ignore_ascii_case("BEGIN:VEVENT") {
			current = Some(VEvent {
				dtstart: None,
				dtend: None,
				rrule: None,
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
		"DTSTART" => event.dtstart = rrule::parse_datetime(value),
		"DTEND" => event.dtend = rrule::parse_datetime(value),
		"RRULE" => event.rrule = Some(value.trim().to_string()),
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

/// Extract the `start`/`end` of a CalDAV `<C:time-range start=... end=.../>` (a
/// free-busy-query). Both are iCalendar UTC datetimes; either may be missing.
/// Returns `None` if neither bound parses.
fn time_range(body: &str) -> Option<Period> {
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
fn itip_range(ics: &str) -> Option<Period> {
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
fn vfreebusy(start: i64, end: i64, periods: &[Period]) -> String {
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

/// One event line in a `calendar-data` multi-status: its href, the file bytes,
/// and the ETag.
struct Event {
	href: String,
	data: Vec<u8>,
	etag: String,
}

/// Read an event at `disk` and, if it is a readable file, append it under
/// `href`. A missing file is skipped — matching how a multiget treats an
/// unknown href.
async fn push_event(entries: &mut Vec<Event>, href: &str, disk: &Path) {
	let Ok(metadata) = tokio::fs::metadata(disk).await else {
		return;
	};
	if !metadata.is_file() {
		return;
	}
	if let Ok(data) = tokio::fs::read(disk).await {
		entries.push(Event {
			href: href.to_string(),
			data,
			etag: super::carddav::etag(&metadata),
		});
	}
}

/// Append every `.ics` directly inside the `collection` directory to `entries`.
async fn collect_events(collection: &Path, entries: &mut Vec<Event>) {
	let Ok(mut dir) = tokio::fs::read_dir(collection).await else {
		return;
	};
	while let Ok(Some(child)) = dir.next_entry().await {
		let name = child.file_name();
		let name = name.to_string_lossy();
		if !is_ics_path(&name) {
			continue;
		}
		let Ok(metadata) = child.metadata().await else {
			continue;
		};
		if !metadata.is_file() {
			continue;
		}
		if let Ok(data) = tokio::fs::read(child.path()).await {
			entries.push(Event {
				href: name.to_string(),
				data,
				etag: super::carddav::etag(&metadata),
			});
		}
	}
}

/// Extract every `<...:href>VALUE</...:href>` value from a REPORT body, matching
/// on the local name `href` regardless of namespace prefix.
fn hrefs(body: &str) -> Vec<String> {
	let mut out = Vec::new();
	let mut rest = body;
	while let Some(start) = find_open(rest, "href") {
		let after = &rest[start..];
		let Some(close) = after.find('>') else {
			break;
		};
		let value_start = close + 1;
		let Some(end) = after[value_start..].find('<') else {
			break;
		};
		let value = after[value_start..value_start + end].trim();
		if !value.is_empty() {
			out.push(value.to_string());
		}
		rest = &after[value_start + end..];
	}
	out
}

/// Find the byte index of an opening tag whose local name is `local`, allowing
/// an optional `prefix:`.
fn find_open(body: &str, local: &str) -> Option<usize> {
	let mut from = 0;
	while let Some(rel) = body[from..].find('<') {
		let lt = from + rel;
		let tag = &body[lt + 1..];
		let name = tag.split(['>', ' ', '/']).next().unwrap_or("");
		let candidate = name.rsplit(':').next().unwrap_or("");
		if candidate == local {
			return Some(lt);
		}
		from = lt + 1;
	}
	None
}

/// Build the `calendar-data` `207 Multi-Status` for the collected events.
fn multistatus(entries: &[Event]) -> Response {
	let mut body = String::from(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
		<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\n",
	);
	for entry in entries {
		let data = escape(&String::from_utf8_lossy(&entry.data));
		body.push_str(&format!(
			"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\t\t<D:propstat>\n\t\t\t<D:prop>\n\
			\t\t\t\t<D:getetag>{etag}</D:getetag>\n\
			\t\t\t\t<C:calendar-data>{data}</C:calendar-data>\n\
			\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 200 OK</D:status>\n\t\t</D:propstat>\n\t</D:response>\n",
			href = escape(&entry.href),
			etag = escape(&entry.etag),
		));
	}
	body.push_str("</D:multistatus>\n");
	(
		StatusCode::MULTI_STATUS,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		body,
	)
		.into_response()
}

#[cfg(test)]
#[path = "caldav_tests.rs"]
mod tests;
