//! The bounds on the work and the memory of one CalDAV or CardDAV `REPORT`.
//!
//! A multiget names its resources one by one and a query walks a whole
//! collection, so neither is bounded by the request alone. Three ceilings
//! keep one request from costing more than a fixed amount:
//!
//! - [`MAX_REPORT_HREFS`] distinct hrefs in a multiget, over which the
//!   request is `413 Payload Too Large`. A repeated href counts once.
//! - [`MAX_REPORT_BYTES`] of resource data in one reply, over which the
//!   request is `507 Insufficient Storage`. The size of a file is checked
//!   before it is read and the read itself is capped, so a file is never
//!   loaded just to be refused.
//! - [`MAX_FILTER_BODY`] bytes for the body of a query or free-busy report,
//!   which only carries a short filter, over which the request is `413`.

use std::path::Path;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::io::AsyncReadExt;

/// How many distinct hrefs one multiget may name.
pub const MAX_REPORT_HREFS: usize = 1000;

/// How many bytes of resource data one reply may carry.
pub const MAX_REPORT_BYTES: u64 = 8 * 1024 * 1024;

/// The largest body a query or free-busy report may have.
pub const MAX_FILTER_BODY: usize = 64 * 1024;

/// Why a report was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
	/// The multiget names more distinct hrefs than allowed.
	TooManyHrefs,
	/// The reply would carry more resource data than allowed.
	TooLarge,
	/// The body of a query or free-busy report is longer than allowed.
	BodyTooLarge,
}

impl Refusal {
	/// The response a refused report answers with.
	pub fn response(&self) -> Response {
		match self {
			Refusal::TooManyHrefs | Refusal::BodyTooLarge => {
				StatusCode::PAYLOAD_TOO_LARGE.into_response()
			}
			Refusal::TooLarge => StatusCode::INSUFFICIENT_STORAGE.into_response(),
		}
	}
}

/// The bytes of resource data a reply may still carry.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
	remaining: u64,
}

impl Budget {
	/// A budget of `limit` bytes.
	pub fn new(limit: u64) -> Self {
		Self { remaining: limit }
	}

	/// The budget of one reply.
	pub fn standard() -> Self {
		Self::new(MAX_REPORT_BYTES)
	}

	/// Spend `len` bytes, or refuse when fewer remain.
	pub fn charge(&mut self, len: u64) -> Result<(), Refusal> {
		self.remaining = self.remaining.checked_sub(len).ok_or(Refusal::TooLarge)?;
		Ok(())
	}
}

/// The distinct hrefs of a multiget in document order, or
/// [`Refusal::TooManyHrefs`] when there are more than `max`.
pub fn distinct_hrefs(hrefs: Vec<String>, max: usize) -> Result<Vec<String>, Refusal> {
	let mut seen = std::collections::HashSet::new();
	let mut out = Vec::new();
	for href in hrefs {
		if seen.insert(href.clone()) {
			if out.len() == max {
				return Err(Refusal::TooManyHrefs);
			}
			out.push(href);
		}
	}
	Ok(out)
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

/// Read one multiget member. `Ok(None)` for a path that is missing or not a
/// file, which a multiget skips; [`Refusal::TooLarge`] when it does not fit
/// what is left of `budget`.
pub async fn read_member(
	disk: &Path,
	budget: &mut Budget,
) -> Result<Option<(Vec<u8>, std::fs::Metadata)>, Refusal> {
	let Ok(metadata) = tokio::fs::metadata(disk).await else {
		return Ok(None);
	};
	if !metadata.is_file() {
		return Ok(None);
	}
	let Some(data) = read_capped(disk, budget.remaining.min(metadata.len())).await else {
		return Err(Refusal::TooLarge);
	};
	budget.charge(data.len() as u64)?;
	Ok(Some((data, metadata)))
}

#[cfg(test)]
#[path = "report_bounds_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "report_bounds_report_tests.rs"]
mod report_tests;
