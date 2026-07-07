//! The `207 Multi-Status` body for `PROPFIND` (RFC 4918 §9.1).
//!
//! We return an `allprop`-style fixed set of live properties — `resourcetype`,
//! `getcontentlength`, `getlastmodified`, `displayname`, `getcontenttype` and
//! `creationdate` — for the target and, at `Depth: 1`, its immediate children.
//! The request body's `<prop>` list is not parsed: returning the standard live
//! props is spec-compliant and what clients expect. The body is assembled by
//! hand with `format!`; no XML dependency is pulled in.

use std::time::SystemTime;

/// One resource line in the multi-status response.
pub struct Entry {
	/// The URI-encoded href as the client should see it (relative to host).
	pub href: String,
	/// Whether this resource is a collection (directory).
	pub is_collection: bool,
	/// Whether this collection is a CardDAV addressbook — adds the
	/// `<C:addressbook/>` resourcetype alongside `<D:collection/>`.
	pub is_addressbook: bool,
	/// Whether this collection is a CalDAV calendar — adds the
	/// `<CAL:calendar/>` resourcetype alongside `<D:collection/>`.
	pub is_calendar: bool,
	/// Byte length for a non-collection; ignored for collections.
	pub length: u64,
	/// Last-modified time, if known.
	pub modified: Option<SystemTime>,
	/// Human-readable name (the last path segment).
	pub display_name: String,
	/// Content type for a non-collection (e.g. `text/vcard` for a vCard).
	pub content_type: &'static str,
	/// A strong-ish ETag, already quoted, for a non-collection; empty to omit.
	pub etag: String,
}

/// Build the full `<multistatus>` document for the given entries.
pub fn multistatus(entries: &[Entry]) -> String {
	let mut body = String::from(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
		<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\" \
		xmlns:CAL=\"urn:ietf:params:xml:ns:caldav\">\n",
	);
	for entry in entries {
		body.push_str(&response(entry));
	}
	body.push_str("</D:multistatus>\n");
	body
}

/// Build a single `<response>` element for one resource.
fn response(entry: &Entry) -> String {
	let resourcetype = if entry.is_collection && entry.is_addressbook {
		"<D:resourcetype><D:collection/><C:addressbook/></D:resourcetype>"
	} else if entry.is_collection && entry.is_calendar {
		"<D:resourcetype><D:collection/><CAL:calendar/></D:resourcetype>"
	} else if entry.is_collection {
		"<D:resourcetype><D:collection/></D:resourcetype>"
	} else {
		"<D:resourcetype/>"
	};
	// Collections do not carry a content length; files do.
	let length = if entry.is_collection {
		String::new()
	} else {
		format!(
			"\t\t\t\t<D:getcontentlength>{}</D:getcontentlength>\n",
			entry.length
		)
	};
	let modified = entry
		.modified
		.map(|time| {
			format!(
				"\t\t\t\t<D:getlastmodified>{}</D:getlastmodified>\n",
				httpdate(time)
			)
		})
		.unwrap_or_default();
	let content_type = if entry.is_collection {
		String::new()
	} else {
		format!(
			"\t\t\t\t<D:getcontenttype>{}</D:getcontenttype>\n",
			entry.content_type
		)
	};
	let etag = if entry.is_collection || entry.etag.is_empty() {
		String::new()
	} else {
		format!("\t\t\t\t<D:getetag>{}</D:getetag>\n", escape(&entry.etag))
	};
	format!(
		"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\t\t<D:propstat>\n\t\t\t<D:prop>\n\
		\t\t\t\t{resourcetype}\n\
		\t\t\t\t<D:displayname>{name}</D:displayname>\n\
		{length}{modified}{content_type}{etag}\
		\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 200 OK</D:status>\n\t\t</D:propstat>\n\t</D:response>\n",
		href = escape(&entry.href),
		name = escape(&entry.display_name),
	)
}

/// Format a `SystemTime` as an IMF-fixdate (RFC 7231) string, the format
/// `getlastmodified` requires, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn httpdate(time: SystemTime) -> String {
	let secs = time
		.duration_since(SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let days = secs / 86_400;
	let rem = secs % 86_400;
	let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
	let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];
	let (year, month, day) = civil_from_days(days as i64);
	let month_name = [
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	][(month - 1) as usize];
	format!("{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
}

/// Convert a day count since the Unix epoch into a civil `(year, month, day)`
/// using Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
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

/// Build the discovery `207 Multi-Status` for `href` (typically a principal or
/// home path) answering the CardDAV and CalDAV bootstrap props:
/// `current-user-principal`, `principal-URL`, `addressbook-home-set`,
/// `calendar-home-set`, and the RFC 6638 scheduling `schedule-outbox-URL` /
/// `schedule-inbox-URL`. The principal and the two homes all point a client at
/// `account_home` (e.g. `/<account>/`); the Outbox and Inbox point at the
/// conventional `<home>outbox/` and `<home>inbox/`. Pragmatic, and enough for
/// autodiscovery to land in the account tree.
pub fn discovery(href: &str, account_home: &str) -> String {
	let href = escape(href);
	let home = escape(account_home);
	let outbox = escape(&format!("{}outbox/", account_home));
	let inbox = escape(&format!("{}inbox/", account_home));
	format!(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
		<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\" \
		xmlns:CAL=\"urn:ietf:params:xml:ns:caldav\">\n\
		\t<D:response>\n\t\t<D:href>{href}</D:href>\n\t\t<D:propstat>\n\t\t\t<D:prop>\n\
		\t\t\t\t<D:current-user-principal><D:href>{home}</D:href></D:current-user-principal>\n\
		\t\t\t\t<D:principal-URL><D:href>{home}</D:href></D:principal-URL>\n\
		\t\t\t\t<C:addressbook-home-set><D:href>{home}</D:href></C:addressbook-home-set>\n\
		\t\t\t\t<CAL:calendar-home-set><D:href>{home}</D:href></CAL:calendar-home-set>\n\
		\t\t\t\t<CAL:schedule-outbox-URL><D:href>{outbox}</D:href></CAL:schedule-outbox-URL>\n\
		\t\t\t\t<CAL:schedule-inbox-URL><D:href>{inbox}</D:href></CAL:schedule-inbox-URL>\n\
		\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 200 OK</D:status>\n\t\t</D:propstat>\n\t</D:response>\n\
		</D:multistatus>\n"
	)
}

/// Whether a PROPFIND request body asks for any of the CardDAV/CalDAV discovery
/// props (`current-user-principal`, `principal-URL`, `addressbook-home-set`,
/// `calendar-home-set`, `schedule-outbox-URL`, `schedule-inbox-URL`). A body
/// requesting one of these is answered with [`discovery`] rather than the
/// filesystem walk.
pub fn wants_discovery(body: &str) -> bool {
	body.contains("current-user-principal")
		|| body.contains("principal-URL")
		|| body.contains("addressbook-home-set")
		|| body.contains("calendar-home-set")
		|| body.contains("schedule-outbox-URL")
		|| body.contains("schedule-inbox-URL")
}

/// Escape the XML special characters for safe interpolation into the body.
pub fn escape(value: &str) -> String {
	value
		.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&apos;")
}

#[cfg(test)]
#[path = "propfind_tests.rs"]
mod tests;
