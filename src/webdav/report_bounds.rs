//! The bounds on the work and the memory of one CalDAV or CardDAV `REPORT`.
//!
//! A multiget names its resources one by one, a query walks a whole
//! collection and a sync lists every member, so none of them is bounded by
//! the request alone. These ceilings keep one request from costing more
//! than a fixed amount:
//!
//! - [`MAX_REPORT_HREFS`] distinct resources in a multiget, over which the
//!   request is `413 Payload Too Large`. Two spellings of the same resource
//!   count once.
//! - [`MAX_REPORT_BYTES`] for the body of one reply, counted after escaping
//!   (see [`super::reply::Reply`]). A resource that does not fit is answered
//!   with its own `507`, and a query that runs out stops with the
//!   `number-of-matches-within-limits` truncation of RFC 4791 and RFC 6578,
//!   so nothing is left out without saying so.
//! - [`MAX_RESOURCE_BYTES`] for one stored `.ics` or `.vcf`. A reply budget
//!   of at least the worst escaped size of one resource means a stored
//!   resource can always be read back on its own.
//! - [`MAX_SYNC_MEMBERS`] members listed by a first `sync-collection`.
//! - [`MAX_FILTER_BODY`] bytes for the body of a query or free-busy report,
//!   which only carries a short filter, over which the request is `413`.

use std::path::Path;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use tokio::io::AsyncReadExt;

/// How many distinct resources one multiget may name.
pub const MAX_REPORT_HREFS: usize = 1000;

/// The largest `.ics` or `.vcf` a `PUT` stores.
pub const MAX_RESOURCE_BYTES: u64 = 4 * 1024 * 1024;

/// The most bytes escaping can make of one byte (`"` becomes `&quot;`).
pub const ESCAPE_EXPANSION: u64 = 6;

/// How many bytes the body of one reply may reach, room for the framing
/// around one resource of [`MAX_RESOURCE_BYTES`] at its worst escaped size.
pub const MAX_REPORT_BYTES: u64 = MAX_RESOURCE_BYTES * ESCAPE_EXPANSION + 64 * 1024;

/// How many members a first `sync-collection` lists.
pub const MAX_SYNC_MEMBERS: usize = super::bounds::MAX_MEMBERS;

/// The largest body a query or free-busy report may have.
pub const MAX_FILTER_BODY: usize = 64 * 1024;

/// Why a report was refused as a whole.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
	/// The multiget names more distinct resources than allowed.
	TooManyHrefs,
	/// The body of a query or free-busy report is longer than allowed.
	BodyTooLarge,
	/// The collection has more members than a first sync lists.
	TooManyMembers,
}

impl Refusal {
	/// The response a refused report answers with, carrying the
	/// `DAV:number-of-matches-within-limits` condition.
	pub fn response(&self) -> Response {
		let status = match self {
			Refusal::TooManyHrefs | Refusal::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
			Refusal::TooManyMembers => StatusCode::INSUFFICIENT_STORAGE,
		};
		(
			status,
			[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
			<D:error xmlns:D=\"DAV:\">\n  <D:number-of-matches-within-limits/>\n</D:error>\n",
		)
			.into_response()
	}
}

/// The hrefs of a multiget in document order, a resource named twice (by
/// the same text or by two spellings that resolve to the same path) kept
/// once, or [`Refusal::TooManyHrefs`] when there are more than `max`.
pub fn distinct_hrefs(root: &Path, hrefs: Vec<String>, max: usize) -> Result<Vec<String>, Refusal> {
	let mut seen = std::collections::HashSet::new();
	let mut out = Vec::new();
	for href in hrefs {
		let key = match super::path::resolve(root, &href) {
			Some(resolved) => resolved.to_string_lossy().into_owned(),
			None => href.clone(),
		};
		if seen.insert(key) {
			if out.len() == max {
				return Err(Refusal::TooManyHrefs);
			}
			out.push(href);
		}
	}
	Ok(out)
}

/// Whether a report asks for the content of each resource. A request that
/// names only `getetag` among the properties gets the etags alone.
pub fn wants_data(body: &str, data_element: &str) -> bool {
	use super::caldav_filter_xml::first_open;
	first_open(body, data_element).is_some() || first_open(body, "getetag").is_none()
}

/// Read `disk` into memory, at most `limit` bytes. `None` when the file is
/// longer, even if it grew after its size was read.
pub async fn read_capped(disk: &Path, limit: u64) -> Option<Vec<u8>> {
	let file = tokio::fs::File::open(disk).await.ok()?;
	let mut data = Vec::new();
	file.take(limit.saturating_add(1))
		.read_to_end(&mut data)
		.await
		.ok()?;
	(data.len() as u64 <= limit).then_some(data)
}

#[cfg(test)]
#[path = "report_bounds_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "report_bounds_report_tests.rs"]
mod report_tests;
