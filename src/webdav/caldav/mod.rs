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

use super::caldav_filter::{MAX_QUERY_WORK, MAX_REQUEST_WORK};
use super::caldav_hrefs::hrefs;
#[cfg(test)]
use super::caldav_hrefs::{SCAN_STEPS, find_open};
use super::path;
use super::reply::{Added, Reply};
use super::report_bounds::{
	MAX_FILTER_BODY, MAX_REPORT_BYTES, MAX_REPORT_HREFS, Refusal, distinct_hrefs, read_capped,
	wants_data,
};
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
/// `calendar-query` honours the filter in `body` (`comp-filter` for
/// `VEVENT`/`VTODO`, `time-range`, and `prop-filter` with `text-match`); an
/// unsupported filter element is `403` with the `CALDAV:supported-filter`
/// precondition rather than being silently ignored. `free-busy-query` scans
/// `target`, expands recurrences over the requested range, and returns a
/// `text/calendar` `VFREEBUSY`. A body naming no report is `400`.
pub async fn report(root: &Path, target: &Path, body: &[u8]) -> Response {
	let text = String::from_utf8_lossy(body);
	let Some(kind) = report_kind(&text) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	let data = wants_data(&text, "calendar-data");
	match kind {
		ReportKind::Multiget => {
			let wanted = match distinct_hrefs(root, hrefs(&text), MAX_REPORT_HREFS) {
				Ok(wanted) => wanted,
				Err(refusal) => return refusal.response(),
			};
			let mut reply = Reply::new(HEAD, MAX_REPORT_BYTES);
			for href in wanted {
				if let Some(resolved) = path::resolve(root, &href)
					&& path::confine_existing(&resolved, root)
					&& let Some(href) = super::href::resource(root, &resolved)
				{
					push_event(&mut reply, &href, &resolved, data).await;
				}
			}
			reply.finish("")
		}
		ReportKind::Query => {
			if body.len() > MAX_FILTER_BODY {
				return Refusal::BodyTooLarge.response();
			}
			let filter = match super::caldav_filter::parse(&text) {
				Ok(filter) => filter,
				Err(_) => return super::caldav_filter::unsupported_filter_response(),
			};
			let mut reply = Reply::new(HEAD, MAX_REPORT_BYTES);
			let request = super::href::resource(root, target).unwrap_or_default();
			collect_events_filtered(root, target, &filter, &request, &mut reply, data).await;
			reply.finish("")
		}
		ReportKind::FreeBusy => {
			if body.len() > MAX_FILTER_BODY {
				return Refusal::BodyTooLarge.response();
			}
			free_busy_report(target, &text).await
		}
	}
}

/// Answer a `free-busy-query`: parse the `<C:time-range>` and emit a
/// `text/calendar` `VFREEBUSY` covering the busy instances in `target`. A
/// missing or malformed range is `400`.
async fn free_busy_report(target: &Path, body: &str) -> Response {
	let Some((start, end)) = time_range(body) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	let periods = match busy_periods(&[target.to_path_buf()], start, end).await {
		Ok(periods) => periods,
		Err(error) => return busy_error(error),
	};
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
	let Ok(calendars) = calendar_dirs(account_root).await else {
		return busy_error(BusyError::Unreadable);
	};
	let periods = match busy_periods(&calendars, start, end).await {
		Ok(periods) => periods,
		Err(error) => return busy_error(error),
	};
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
/// scans them all so it reflects the account's whole schedule. Children that
/// are themselves symlinks (planted escapes) are skipped.
async fn calendar_dirs(root: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
	let mut out = Vec::new();
	if is_calendar(root) {
		out.push(root.to_path_buf());
	}
	let mut dir = match tokio::fs::read_dir(root).await {
		Ok(dir) => dir,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
		Err(error) => return Err(error),
	};
	while let Some(child) = dir.next_entry().await? {
		let Ok(kind) = child.file_type().await else {
			continue;
		};
		if !crate::util::fs_walk::allowed(&child.path(), kind) {
			continue;
		}
		let path = child.path();
		if let Ok(meta) = std::fs::symlink_metadata(&path)
			&& meta.file_type().is_symlink()
		{
			continue;
		}
		if is_calendar(&path) {
			out.push(path);
		}
	}
	Ok(out)
}

/// A busy period: `[start, end)` epoch seconds.
pub(super) type Period = (i64, i64);

use super::caldav_busy::{BusyError, busy_periods};

/// The reply to a free-busy request that cannot be answered truthfully:
/// `403` with the `DAV:number-of-matches-within-limits` precondition
/// (RFC 4791 §1.3 / RFC 3744 §7.1.1) when it asks for more work than one
/// request may take, so the client can narrow the range; `403` naming the
/// recurrence when an event repeats by a rule that is not evaluated; `500`
/// when a calendar cannot be read. Never a partial answer, which would read
/// as free time.
fn busy_error(error: BusyError) -> Response {
	match error {
		BusyError::TooMuchWork => (
			StatusCode::FORBIDDEN,
			[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error xmlns:D=\"DAV:\"><D:number-of-matches-within-limits/></D:error>",
		)
			.into_response(),
		BusyError::Unsupported => (
			StatusCode::FORBIDDEN,
			[(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
			"an event repeats by a rule this server does not evaluate",
		)
			.into_response(),
		BusyError::Unreadable => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	}
}

/// The opening of a `calendar-data` multistatus.
const HEAD: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
	<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\n";

/// Read the event at `disk` and, if it is a readable file, add it under
/// `href`. A missing file is skipped, matching how a multiget treats an
/// unknown href; one that does not fit what is left of the reply is
/// answered `507` so the client asks for it on its own.
async fn push_event(reply: &mut Reply, href: &str, disk: &Path, data: bool) {
	let Ok(metadata) = tokio::fs::metadata(disk).await else {
		return;
	};
	if !metadata.is_file() {
		return;
	}
	let etag = super::carddav::etag(&metadata);
	if !data {
		if reply.member(href, &etag, None) == Added::NoRoom {
			reply.too_large(href);
		}
		return;
	}
	match read_capped(disk, metadata.len().min(reply.remaining())).await {
		Some(bytes) => {
			if reply.member(href, &etag, Some(("C:calendar-data", &bytes))) == Added::NoRoom {
				reply.too_large(href);
			}
		}
		None => reply.too_large(href),
	}
}

/// Append every `.ics` directly inside the `collection` directory to
/// `entries`, applying the `filter` (RFC 4791 §9.7) to each file: a
/// resource whose `.ics` body does not match the filter is skipped.
/// Children that are themselves symlinks are skipped, they may have
/// been planted in the user's tree, and following them would read
/// events that belong to no account.
async fn collect_events_filtered(
	root: &Path,
	collection: &Path,
	filter: &super::caldav_filter::CalendarQueryFilter,
	request: &str,
	reply: &mut Reply,
	data: bool,
) {
	let Ok(mut dir) = tokio::fs::read_dir(collection).await else {
		return;
	};
	// One budget for the whole request: every object draws from it, so the
	// per-object bound cannot be multiplied by the size of the collection.
	let mut request_left = MAX_REQUEST_WORK;
	while let Ok(Some(child)) = dir.next_entry().await {
		let Ok(kind) = child.file_type().await else {
			continue;
		};
		if !crate::util::fs_walk::allowed(&child.path(), kind) {
			continue;
		}
		let name = child.file_name();
		let name = name.to_string_lossy();
		if !is_ics_path(&name) {
			continue;
		}
		if let Ok(sym) = std::fs::symlink_metadata(child.path())
			&& sym.file_type().is_symlink()
		{
			continue;
		}
		let Ok(metadata) = child.metadata().await else {
			continue;
		};
		if !metadata.is_file() {
			continue;
		}
		let Some(href) = super::href::resource(root, &child.path()) else {
			continue;
		};
		// A file longer than a whole reply can be neither filtered nor
		// returned: say so instead of leaving it out.
		if metadata.len() > MAX_REPORT_BYTES {
			reply.too_large(&href);
			continue;
		}
		let Some(bytes) = read_capped(&child.path(), MAX_REPORT_BYTES).await else {
			reply.too_large(&href);
			continue;
		};
		// Apply the filter. An empty filter (no `comp-filter`
		// children) is a no-op, so the call is cheap.
		let text = String::from_utf8_lossy(&bytes);
		// An object gets the smaller of its own bound and what the request
		// has left, and pays for what it spends.
		let mut left = request_left.min(MAX_QUERY_WORK);
		let granted = left;
		let verdict = super::caldav_filter::matches_within(filter, &text, &mut left);
		request_left -= granted - left;
		match verdict {
			Ok(true) => {}
			Ok(false) => continue,
			Err(_) if granted < MAX_QUERY_WORK => {
				// The request ran out of work, not the object: nothing
				// after this point can be searched, so say the answer is
				// cut short instead of leaving the rest out.
				reply.truncated(request);
				return;
			}
			Err(_) => {
				// The object could not be searched within the work bound:
				// a series it holds may still fall inside the window, so
				// it is answered on its own instead of being left out.
				reply.too_large(&href);
				continue;
			}
		}
		let etag = super::carddav::etag(&metadata);
		if reply.member(
			&href,
			&etag,
			data.then_some(("C:calendar-data", &bytes[..])),
		) == Added::Yes
		{
			continue;
		}
		if reply.members() == 0 {
			reply.too_large(&href);
		} else {
			reply.truncated(request);
			return;
		}
	}
}

mod freebusy_text;
mod vevent;

use freebusy_text::{itip_range, time_range, vfreebusy};
pub use vevent::unfold;
pub(super) use vevent::vevents;

#[cfg(test)]
mod tests;
