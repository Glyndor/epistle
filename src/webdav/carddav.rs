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

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::path;
use super::propfind::escape;

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
/// served). `addressbook-query` ignores the filter — a valid, widely-used
/// simplification — and returns every `.vcf` in the target collection. Both
/// reply `207 Multi-Status` with `address-data` + `getetag` per card. A body
/// naming neither report is `400`.
pub async fn report(root: &Path, target: &Path, body: &[u8]) -> Response {
	let text = String::from_utf8_lossy(body);
	let Some(kind) = report_kind(&text) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	let mut entries = Vec::new();
	match kind {
		ReportKind::Multiget => {
			for href in hrefs(&text) {
				if let Some(resolved) = path::resolve(root, &href) {
					push_card(&mut entries, &href, &resolved).await;
				}
			}
		}
		ReportKind::Query => {
			collect_cards(target, &mut entries).await;
		}
	}
	multistatus(&entries).into_response()
}

/// One card line in an `address-data` multi-status: its href, the file bytes,
/// and the ETag.
struct Card {
	href: String,
	data: Vec<u8>,
	etag: String,
}

/// Read a card at `disk` and, if it is a readable file, append it to `entries`
/// under `href`. A missing file or read error is skipped (it simply does not
/// appear in the 207) — matching how a multiget treats an unknown href.
async fn push_card(entries: &mut Vec<Card>, href: &str, disk: &Path) {
	let Ok(metadata) = tokio::fs::metadata(disk).await else {
		return;
	};
	if !metadata.is_file() {
		return;
	}
	if let Ok(data) = tokio::fs::read(disk).await {
		entries.push(Card {
			href: href.to_string(),
			data,
			etag: etag(&metadata),
		});
	}
}

/// Append every `.vcf` directly inside the `collection` directory to `entries`.
/// The child href is the collection path plus the file name. A non-directory
/// target yields nothing.
async fn collect_cards(collection: &Path, entries: &mut Vec<Card>) {
	let Ok(mut dir) = tokio::fs::read_dir(collection).await else {
		return;
	};
	while let Ok(Some(child)) = dir.next_entry().await {
		let name = child.file_name();
		let name = name.to_string_lossy();
		if !is_vcard_path(&name) {
			continue;
		}
		let Ok(metadata) = child.metadata().await else {
			continue;
		};
		if !metadata.is_file() {
			continue;
		}
		if let Ok(data) = tokio::fs::read(child.path()).await {
			entries.push(Card {
				href: name.to_string(),
				data,
				etag: etag(&metadata),
			});
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
/// The local name is the tag name (up to the first `>`, space or `/`) with any
/// `prefix:` stripped.
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

/// Build the `address-data` `207 Multi-Status` for the collected cards.
fn multistatus(entries: &[Card]) -> Response {
	let mut body = String::from(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
		<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\n",
	);
	for entry in entries {
		let data = escape(&String::from_utf8_lossy(&entry.data));
		body.push_str(&format!(
			"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\t\t<D:propstat>\n\t\t\t<D:prop>\n\
			\t\t\t\t<D:getetag>{etag}</D:getetag>\n\
			\t\t\t\t<C:address-data>{data}</C:address-data>\n\
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
#[path = "carddav_tests.rs"]
mod tests;
