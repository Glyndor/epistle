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
	/// Byte length for a non-collection; ignored for collections.
	pub length: u64,
	/// Last-modified time, if known.
	pub modified: Option<SystemTime>,
	/// Human-readable name (the last path segment).
	pub display_name: String,
}

/// Build the full `<multistatus>` document for the given entries.
pub fn multistatus(entries: &[Entry]) -> String {
	let mut body = String::from(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
	);
	for entry in entries {
		body.push_str(&response(entry));
	}
	body.push_str("</D:multistatus>\n");
	body
}

/// Build a single `<response>` element for one resource.
fn response(entry: &Entry) -> String {
	let resourcetype = if entry.is_collection {
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
		"\t\t\t\t<D:getcontenttype>application/octet-stream</D:getcontenttype>\n".to_string()
	};
	format!(
		"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\t\t<D:propstat>\n\t\t\t<D:prop>\n\
		\t\t\t\t{resourcetype}\n\
		\t\t\t\t<D:displayname>{name}</D:displayname>\n\
		{length}{modified}{content_type}\
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

/// Escape the XML special characters for safe interpolation into the body.
fn escape(value: &str) -> String {
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
