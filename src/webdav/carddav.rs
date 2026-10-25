//! CardDAV (RFC 6352) extensions layered onto the base WebDAV server.
//!
//! CardDAV is served over the very same router and per-account confinement as
//! WebDAV: a vCard is just a `.vcf` file, an addressbook is just a collection
//! marked as one. This module adds the pieces that make those files
//! discoverable and queryable by a CardDAV client (Evolution, Thunderbird, …):
//!
//! - the addressbook marker — a collection becomes an addressbook when it holds
//!   a [`MARKER`] file ([`is_addressbook`]/[`mark_addressbook`]); this keeps the
//!   mechanism simple and robust without a metadata store.
//! - the [`REPORT`](report) method, dispatching on the request body's root
//!   element into `addressbook-multiget` and `addressbook-query`.
//! - the `address-data`/`getetag` `207 Multi-Status` builder.
//! - the discovery props (`current-user-principal`, `addressbook-home-set`,
//!   `principal-URL`) a client needs to find the addressbook home.
//!
//! Every href a client names in a REPORT is resolved through [`path::resolve`],
//! exactly like every other request path, so a REPORT can never read another
//! account's cards nor escape the account root via `..` — confinement is the
//! same fail-closed gate as the rest of the module.

use std::path::Path;
use std::time::SystemTime;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::path;
use super::reply::{Added, Reply};
use super::report_bounds::{
	MAX_FILTER_BODY, MAX_REPORT_BYTES, MAX_REPORT_HREFS, Refusal, distinct_hrefs, read_capped,
};

/// The CardDAV XML namespace.
pub const CARDDAV_NS: &str = "urn:ietf:params:xml:ns:carddav";

/// The marker file that flags a collection as an addressbook. It lives inside
/// the collection directory; its presence is the whole signal.
pub const MARKER: &str = ".addressbook";

/// The `Content-Type` for a vCard resource.
pub const VCARD_TYPE: &str = "text/vcard";

/// Whether `dir` is an addressbook collection — i.e. it is a directory holding
/// the [`MARKER`] file.
pub fn is_addressbook(dir: &Path) -> bool {
	dir.is_dir() && dir.join(MARKER).is_file()
}

/// Create the [`MARKER`] inside an existing collection directory, flagging it as
/// an addressbook. Returns whether the marker is now present.
pub async fn mark_addressbook(dir: &Path) -> bool {
	tokio::fs::write(dir.join(MARKER), b"").await.is_ok()
}

/// Whether a request path names a vCard resource (a `.vcf` file, by extension).
pub fn is_vcard_path(uri_path: &str) -> bool {
	uri_path.to_ascii_lowercase().ends_with(".vcf")
}

/// A strong-ish ETag for a resource, derived from its size and modification
/// time. Stable across reads, changes on every write — enough for a client to
/// detect a card has changed. The value is already quoted, ready for the
/// `ETag` header or a `<D:getetag>` element.
pub fn etag(metadata: &std::fs::Metadata) -> String {
	let modified = metadata
		.modified()
		.ok()
		.and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
		.map(|d| d.as_nanos())
		.unwrap_or(0);
	format!("\"{:x}-{:x}\"", metadata.len(), modified)
}

/// Detect a REPORT's type from its body without a full XML parse: scan for the
/// first CardDAV report root element. Returns the matching [`ReportKind`], or
/// `None` for a body that names neither report.
pub fn report_kind(body: &str) -> Option<ReportKind> {
	let multiget = body.find("addressbook-multiget");
	let query = body.find("addressbook-query");
	match (multiget, query) {
		(Some(m), Some(q)) if q < m => Some(ReportKind::Query),
		(Some(_), _) => Some(ReportKind::Multiget),
		(None, Some(_)) => Some(ReportKind::Query),
		(None, None) => None,
	}
}

/// The two CardDAV REPORTs this server answers.
#[derive(Debug, PartialEq, Eq)]
pub enum ReportKind {
	/// `addressbook-multiget`: return the explicitly listed hrefs.
	Multiget,
	/// `addressbook-query`: return every card in the target collection.
	Query,
}

/// Handle a CardDAV `REPORT` against `target` (the request-path resource).
///
/// `addressbook-multiget` returns each `<D:href>` named in `body` (resolved
/// through `root`, so a traversal or cross-account href is silently dropped, not
/// served). `addressbook-query` honours the `<CR:filter>` in `body`
/// (`prop-filter` with `text-match`; the `test="anyof"|"allof"` attribute
/// combines multiple prop-filters; `is-not-defined` is also honoured). An
/// unsupported filter element answers `403 Forbidden` with the
/// `CARDDAV:supported-filter` precondition rather than being silently
/// ignored. Both reports reply `207 Multi-Status` with `address-data` +
/// `getetag` per card. A body naming neither report is `400`.
pub async fn report(root: &Path, target: &Path, body: &[u8]) -> Response {
	let text = String::from_utf8_lossy(body);
	let Some(kind) = report_kind(&text) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	let mut reply = Reply::new(HEAD, MAX_REPORT_BYTES);
	match kind {
		ReportKind::Multiget => {
			let wanted = match distinct_hrefs(root, hrefs(&text), MAX_REPORT_HREFS) {
				Ok(wanted) => wanted,
				Err(refusal) => return refusal.response(),
			};
			for href in wanted {
				if let Some(resolved) = path::resolve(root, &href)
					&& path::confine_existing(&resolved, root)
					&& let Some(href) = super::href::resource(root, &resolved)
				{
					push_card(&mut reply, &href, &resolved).await;
				}
			}
		}
		ReportKind::Query => {
			if body.len() > MAX_FILTER_BODY {
				return Refusal::BodyTooLarge.response();
			}
			let filter = match super::carddav_filter::parse(&text) {
				Ok(filter) => filter,
				Err(_) => return super::carddav_filter::unsupported_filter_response(),
			};
			let request = super::href::resource(root, target).unwrap_or_default();
			collect_cards_filtered(root, target, &filter, &request, &mut reply).await;
		}
	}
	reply.finish("")
}

/// The opening of an `address-data` multistatus.
const HEAD: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
	<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\n";

/// Read the card at `disk` and, if it is a readable file, add it under
/// `href`. A missing file is skipped, matching how a multiget treats an
/// unknown href; one that does not fit what is left of the reply is
/// answered `507` so the client asks for it on its own.
async fn push_card(reply: &mut Reply, href: &str, disk: &Path) {
	let Ok(metadata) = tokio::fs::metadata(disk).await else {
		return;
	};
	if !metadata.is_file() {
		return;
	}
	let etag = etag(&metadata);
	match read_capped(disk, metadata.len().min(reply.remaining())).await {
		Some(data) => {
			if reply.member(href, &etag, Some(("C:address-data", &data))) == Added::NoRoom {
				reply.too_large(href);
			}
		}
		None => reply.too_large(href),
	}
}

/// Append every `.vcf` directly inside the `collection` directory to
/// `entries`, applying the `filter` to each card: a card whose body
/// does not match the filter is skipped. Children that are themselves
/// symlinks are skipped, they may have been planted in the user's
/// tree, and following them would read cards that belong to no
/// account.
async fn collect_cards_filtered(
	root: &Path,
	collection: &Path,
	filter: &super::carddav_filter::AddressbookQueryFilter,
	request: &str,
	reply: &mut Reply,
) {
	let Ok(mut dir) = tokio::fs::read_dir(collection).await else {
		return;
	};
	while let Ok(Some(child)) = dir.next_entry().await {
		let Ok(kind) = child.file_type().await else {
			continue;
		};
		if !crate::util::fs_walk::allowed(&child.path(), kind) {
			continue;
		}
		let name = child.file_name();
		let name = name.to_string_lossy();
		if !is_vcard_path(&name) {
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
		let Some(data) = read_capped(&child.path(), MAX_REPORT_BYTES).await else {
			reply.too_large(&href);
			continue;
		};
		// Apply the filter. An empty filter (no `prop-filter`
		// children) is a no-op, so the call is cheap.
		let text = String::from_utf8_lossy(&data);
		if !super::carddav_filter::matches(filter, &text) {
			continue;
		}
		if reply.member(&href, &etag(&metadata), Some(("C:address-data", &data))) == Added::Yes {
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

/// Extract every `<...:href>VALUE</...:href>` value from a REPORT body. The
/// namespace prefix is irrelevant, so we match on the local name `href`. Values
/// are returned in document order, untrimmed of surrounding whitespace beyond a
/// trim of the captured text.
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
/// an optional `prefix:` (e.g. `<D:href>` or `<href>`) — the index of the `<`.
/// The local name is the tag name (up to the first `>`, space, `/` or the
/// next `<`) with any `prefix:` stripped.
///
/// The implementation walks the body once, byte by byte. The previous
/// quadratic version restarted the search from the cursor after every
/// non-match, and `tag.split(['>', ' ', '/']).next()` returned the whole
/// remaining tail as one piece when the tag was unclosed, so a body of
/// N unclosed tags cost O(N²) bytes touched. The linear scan advances
/// past the tag name in one jump and bounds the name by the next `<`
/// when no closing delimiter is found, so the total stays O(N) bytes
/// touched. The byte counter [`SCAN_STEPS`] is exposed for tests that
/// want to assert the bound.
fn find_open(body: &str, local: &str) -> Option<usize> {
	let bytes = body.as_bytes();
	let needle = local.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		#[cfg(test)]
		{
			SCAN_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		}
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		// Parse the tag name: characters up to the first '>', ' ', '/',
		// or the next '<' (an unclosed tag). The previous version only
		// looked for '>', ' ', '/'; an unclosed tag made the rest of
		// the body count as the tag name, which is what produced the
		// quadratic behaviour. Treating the next '<' as a delimiter
		// bounds the per-tag scan to the distance to the next tag.
		let name_start = i + 1;
		let mut name_end = name_start;
		while name_end < bytes.len() {
			#[cfg(test)]
			{
				SCAN_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			}
			let c = bytes[name_end];
			if c == b'>' || c == b' ' || c == b'/' || c == b'<' {
				break;
			}
			name_end += 1;
		}
		// Find the local name (after the last `:` if any).
		let mut local_start = name_start;
		for (k, b) in bytes[name_start..name_end].iter().enumerate() {
			#[cfg(test)]
			{
				SCAN_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			}
			if *b == b':' {
				local_start = name_start + k + 1;
			}
		}
		let local_len = name_end - local_start;
		if local_len == needle.len() && &bytes[local_start..name_end] == needle {
			return Some(i);
		}
		// Skip past the whole tag name in one jump, at minimum one byte
		// (`<x>` has no payload), the worst case is the name itself.
		i = name_end.max(i + 1);
	}
	None
}

/// Per-process counter of how many bytes the report scanner compared.
/// Read in tests to assert the body scan is linear, not quadratic.
#[cfg(test)]
static SCAN_STEPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
#[path = "carddav_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "carddav_filter_integration_tests.rs"]
mod filter_integration_tests;

#[cfg(test)]
#[path = "carddav_scan_tests.rs"]
mod scan_tests;
