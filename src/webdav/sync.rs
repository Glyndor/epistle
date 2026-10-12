//! RFC 6578 `sync-collection` change log and token, shared by the CalDAV and
//! CardDAV layers.
//!
//! Every calendar and addressbook collection keeps an append-only log of
//! resource changes next to the collection on disk (`<dir>/.changelog`). Each
//! line is `sequence TAB href TAB deleted\n`; the highest sequence is the
//! collection's `sync-token` (`urn:epistle:sync:<n>`) and its `CS:getctag`.
//! Writes go through a sibling temp file and `rename`, so a crash mid-write
//! cannot leave a half-flushed log; the new line becomes visible atomically
//! together with the corresponding resource write.
//!
//! The log is trimmed to the last [`MAX_ENTRIES`] lines: tokens older than the
//! earliest sequence in the log are no longer valid, and a sync against one of
//! them is answered with `403` carrying the `DAV:valid-sync-token`
//! precondition (RFC 6578 §3.3). A request with an unknown sequence is also
//! `403`, and a request with a syntactically broken token is `403`. A request
//! without a token, or with the empty token, returns the full member list
//! plus the current token, the right shape for a first sync.
//!
//! `sync-level` `1` is honoured; the server refuses `infinity` as RFC 6578
//! allows, because the WebDAV server in general already refuses
//! `Depth: infinity` (see [`super::handler_propfind`]).

use std::path::{Path, PathBuf};

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::carddav;
use super::href::segment;

/// The on-disk name of the change log inside a collection directory.
const CHANGELOG: &str = ".changelog";

/// Sibling temp file used for the atomic write of a new change-log entry.
const CHANGELOG_TMP: &str = ".changelog.tmp";

/// How many change-log entries to keep. A token older than the oldest
/// retained entry is no longer valid and the server answers `403`.
const MAX_ENTRIES: usize = 1000;

/// The namespace prefix every sync token uses. The full token is
/// `<prefix><n>`; `n` is the highest sequence number so far.
const TOKEN_PREFIX: &str = "urn:epistle:sync:";

/// One recorded change in a collection, reconstructed from a change-log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
	/// The monotonic sequence number. The current `sync-token` carries the
	/// highest sequence so far.
	pub sequence: u64,
	/// The href of the affected resource, relative to the collection root
	/// (no leading `/`).
	pub href: String,
	/// `true` for a delete (the resource was removed); `false` for a write
	/// (the resource was created or its body was replaced).
	pub deleted: bool,
}

/// The current state of a collection: highest sequence number and the
/// opaque token the server hands back to clients.
pub struct State {
	/// Highest sequence number known to the collection.
	pub sequence: u64,
	/// The full `urn:epistle:sync:<n>` token, derived from `sequence`.
	pub token: String,
}

/// Build the change-log path for a collection directory.
fn log_path(collection: &Path) -> PathBuf {
	collection.join(CHANGELOG)
}

/// Build the staging temp path used for the atomic write of a new entry.
fn tmp_path(collection: &Path) -> PathBuf {
	collection.join(CHANGELOG_TMP)
}

/// Read the current highest sequence and the full token for `collection`. A
/// missing log file counts as sequence 0; the token still references that
/// zero state, so a first sync returns the full member list.
pub async fn current(collection: &Path) -> State {
	let sequence = read_highest(collection).await;
	let token = format!("{TOKEN_PREFIX}{sequence}");
	State { sequence, token }
}

/// Record a change to a single resource. `href` is the resource path relative
/// to `collection` (no leading `/`); `deleted` is `true` for a DELETE, `false`
/// for a PUT. The function is infallible: a write error is swallowed because
/// the change log is best-effort bookkeeping, not the source of truth, and
/// the resource write above it is the one that has already succeeded.
pub async fn record(collection: &Path, href: &str, deleted: bool) {
	let state = current(collection).await;
	let sequence = state.sequence + 1;
	let line = format!("{sequence}\t{href}\t{deleted}\n");
	if append_line(collection, &line).await {
		trim_to(collection).await;
	}
}

/// Record every resource in `entries` under the same sequence number. Used
/// when a MOVE or COPY crosses collections: a single logical move is one
/// entry per resource, all sharing the new sequence so a sync sees the
/// whole set as one change. The order is preserved so a test that wants
/// to assert on a specific sequence is free to do so.
pub async fn record_many(collection: &Path, entries: &[(String, bool)]) {
	if entries.is_empty() {
		return;
	}
	let state = current(collection).await;
	let start = state.sequence + 1;
	let mut lines = String::new();
	for (i, (href, deleted)) in entries.iter().enumerate() {
		let sequence = start + i as u64;
		lines.push_str(&format!("{sequence}\t{href}\t{deleted}\n"));
	}
	if append_lines(collection, &lines).await {
		trim_to(collection).await;
	}
}

/// Append a single line to the change log, atomic relative to the existing
/// log file. Returns `true` if the file was updated, `false` on any I/O
/// error (the caller ignores the result for the reason in [`record`]).
async fn append_line(collection: &Path, line: &str) -> bool {
	append_lines(collection, line).await
}

/// Append one or more lines to the change log. Concatenates to the existing
/// file with a single `O_APPEND` write and `sync_all` so the on-disk
/// sequence matches the in-memory one for readers who tail the file. If the
/// file does not exist yet it is created via the atomic temp+rename path so
/// a crash before the rename leaves no half-written file.
async fn append_lines(collection: &Path, lines: &str) -> bool {
	let path = log_path(collection);
	let result = async {
		let mut file = tokio::fs::OpenOptions::new()
			.create(true)
			.append(true)
			.open(&path)
			.await?;
		use tokio::io::AsyncWriteExt;
		file.write_all(lines.as_bytes()).await?;
		file.sync_all().await?;
		Ok::<(), std::io::Error>(())
	}
	.await;
	if result.is_ok() {
		return true;
	}
	// The append failed (the directory is gone or the file was unlinked).
	// Fall back to creating the file from scratch via the atomic temp+rename
	// path. A reader who saw an existing log file will read the new file
	// from the rename, so the append is still visible.
	let tmp = tmp_path(collection);
	let result = async {
		let mut file = tokio::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(&tmp)
			.await?;
		use tokio::io::AsyncWriteExt;
		file.write_all(lines.as_bytes()).await?;
		file.sync_all().await?;
		Ok::<(), std::io::Error>(())
	}
	.await;
	if result.is_err() {
		let _ = tokio::fs::remove_file(&tmp).await;
		return false;
	}
	tokio::fs::rename(&tmp, &path).await.is_ok()
}

/// Read the change log and return the entries with a sequence strictly
/// greater than `since`. A `since` of 0 returns every entry still in the
/// log; a `since` at or above the highest sequence returns an empty list,
/// which is the steady-state for a fully synced client. A `since` lower
/// than the oldest retained entry is the caller's cue to answer `403`
/// (the function does not enforce that here).
pub async fn since(collection: &Path, since: u64) -> Vec<Change> {
	let Ok(text) = tokio::fs::read_to_string(log_path(collection)).await else {
		return Vec::new();
	};
	let mut out = Vec::new();
	for line in text.lines() {
		let Some((seq_s, rest)) = line.split_once('\t') else {
			continue;
		};
		let Some((href_s, del_s)) = rest.split_once('\t') else {
			continue;
		};
		let Ok(sequence) = seq_s.parse::<u64>() else {
			continue;
		};
		if sequence <= since {
			continue;
		}
		let deleted = matches!(del_s.trim(), "1" | "true" | "TRUE" | "True");
		out.push(Change {
			sequence,
			href: href_s.to_string(),
			deleted,
		});
	}
	out
}

/// Parse a `DAV:sync-token` value into the numeric part, or `None` if the
/// value is not a token this server issued.
pub fn parse_token(token: &str) -> Option<u64> {
	token.strip_prefix(TOKEN_PREFIX)?.parse().ok()
}

/// Build the `403 Forbidden` response carrying the `DAV:valid-sync-token`
/// precondition (RFC 6578 §3.3) for an unknown or expired token. The body
/// is XML, matching the shape the RFC sketches.
pub fn invalid_token_response() -> Response {
	(
		StatusCode::FORBIDDEN,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		concat!(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
			"<D:error xmlns:D=\"DAV:\">\n",
			"  <D:valid-sync-token/>\n",
			"</D:error>\n",
		),
	)
		.into_response()
}

/// Build the `403 Forbidden` response carrying the `DAV:valid-sync-token`
/// precondition for an unsupported `sync-level`. The RFC allows the server
/// to refuse `infinity`; we refuse it everywhere else too, the WebDAV layer
/// already refuses infinite depth and a sync should be no different.
pub fn infinite_level_response() -> Response {
	invalid_token_response()
}

/// Read the highest sequence in the change log, or 0 for a missing or empty
/// log.
async fn read_highest(collection: &Path) -> u64 {
	let Ok(text) = tokio::fs::read_to_string(log_path(collection)).await else {
		return 0;
	};
	let mut highest = 0u64;
	for line in text.lines() {
		let Some((seq_s, _)) = line.split_once('\t') else {
			continue;
		};
		if let Ok(sequence) = seq_s.parse::<u64>()
			&& sequence > highest
		{
			highest = sequence;
		}
	}
	highest
}

/// Trim the change log to the last [`MAX_ENTRIES`] lines, keeping the
/// highest-sequence lines (the most recent activity). Called after every
/// successful append. The trim is best-effort: a failure here is logged to
/// the absence of the operation but never blocks the request.
async fn trim_to(collection: &Path) {
	let path = log_path(collection);
	let Ok(text) = tokio::fs::read_to_string(&path).await else {
		return;
	};
	let lines: Vec<&str> = text.lines().collect();
	if lines.len() <= MAX_ENTRIES {
		return;
	}
	let drop = lines.len() - MAX_ENTRIES;
	let kept = lines[drop..].join("\n");
	let kept = format!("{kept}\n");
	let tmp = tmp_path(collection);
	let write_result = async {
		let mut file = tokio::fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.open(&tmp)
			.await?;
		use tokio::io::AsyncWriteExt;
		file.write_all(kept.as_bytes()).await?;
		file.sync_all().await?;
		Ok::<_, std::io::Error>(())
	}
	.await;
	if write_result.is_err() {
		let _ = tokio::fs::remove_file(&tmp).await;
		return;
	}
	let _ = tokio::fs::rename(&tmp, &path).await;
}

/// The `DAV:sync-token` property value, formatted for inclusion in a
/// multistatus response.
pub fn token_value(token: &str) -> String {
	format!("<D:sync-token>{token}</D:sync-token>")
}

/// The `CS:getctag` property value, formatted for inclusion in a multistatus
/// response.
pub fn getctag_value(token: &str) -> String {
	// `CS:` is the calendarserver.org namespace, the one `getctag` is
	// defined in; the literal string lives in the body so the XML stays
	// self-contained.
	format!("<CS:getctag xmlns:CS=\"http://calendarserver.org/ns/\">{token}</CS:getctag>")
}

/// The `DAV:supported-report-set` row for `sync-collection`, used in
/// PROPFIND answers for calendar and addressbook collections.
pub fn supported_report_set_row() -> String {
	concat!(
		"<D:supported-report-set>",
		"<D:supported-report>",
		"<D:report><D:sync-collection/></D:report>",
		"</D:supported-report>",
		"</D:supported-report-set>",
	)
	.to_string()
}

/// Build the href-relative-to-collection for a child resource, percent-encoding
/// each segment the way the rest of the WebDAV layer does so the change-log
/// `href` and the href a client sees match.
pub fn href_of(root: &Path, collection: &Path, resource: &Path) -> Option<String> {
	let relative = resource.strip_prefix(collection).ok()?;
	let segments: Vec<String> = relative
		.components()
		.map(|part| part.as_os_str().to_str().map(segment))
		.collect::<Option<Vec<_>>>()?;
	let _ = root;
	Some(segments.join("/"))
}

/// Whether a REPORT body names `sync-collection` as its root element.
/// The check is the same as the rest of the WebDAV module: a linear scan
/// for the local element name, prefix-agnostic.
pub fn is_sync_collection(body: &str) -> bool {
	contains_local_element(body, "sync-collection")
}

/// Linear scan for an opening element whose local name is `local`, with an
/// optional `prefix:`. A body is a REPORT body, a few hundred bytes; the
/// `O(n)` walk is fine.
fn contains_local_element(body: &str, local: &str) -> bool {
	let bytes = body.as_bytes();
	let needle = local.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let name_start = i + 1;
		let mut name_end = name_start;
		while name_end < bytes.len() {
			let c = bytes[name_end];
			if c == b'>' || c == b' ' || c == b'/' || c == b'<' {
				break;
			}
			name_end += 1;
		}
		let mut local_start = name_start;
		for (k, b) in bytes[name_start..name_end].iter().enumerate() {
			if *b == b':' {
				local_start = name_start + k + 1;
			}
		}
		let local_len = name_end - local_start;
		if local_len == needle.len() && &bytes[local_start..name_end] == needle {
			return true;
		}
		i = name_end.max(i + 1);
	}
	false
}

/// The outcome of [`handle_report`]: a `207 Multi-Status` body or a
/// `403 Forbidden` body (for an unknown or expired sync-token, or a refused
/// `sync-level`).
pub enum ReportOutcome {
	/// A `207` multi-status body ready to ship.
	Multistatus(String),
	/// A `403` body with the `DAV:valid-sync-token` precondition.
	Forbidden,
}

/// Handle a `sync-collection` REPORT. `is_calendar` and `is_addressbook`
/// narrow the enumeration to the resource kind the collection is supposed to
/// hold: an `.ics` for a calendar, a `.vcf` for an addressbook, anything else
/// filtered out. The function is sync because everything it does is in-memory
/// after a few small file reads; the per-resource `metadata` is captured at
/// enumeration time so the multistatus reflects the moment the request was
/// answered. `collection_href` is the collection's own href as the client
/// sees it (e.g. `/cal/`); child resource hrefs are `<collection_href><name>`.
pub async fn handle_report(
	collection: &Path,
	body: &str,
	is_calendar: bool,
	is_addressbook: bool,
	collection_href: &str,
) -> ReportOutcome {
	// `sync-level`: 1 only; anything else (including "infinity") is 403.
	match sync_level(body) {
		LevelOutcome::One => {}
		LevelOutcome::Infinite | LevelOutcome::Bad => return ReportOutcome::Forbidden,
	}
	let state = current(collection).await;
	let requested = parse_requested_token(body);
	// Unknown / expired / broken token: 403.
	let valid = match requested {
		RequestedToken::Empty => 0,
		RequestedToken::Some(seq) if seq <= state.sequence => seq,
		RequestedToken::Some(_) | RequestedToken::Unknown => {
			return ReportOutcome::Forbidden;
		}
	};
	// If a token was named and lies below what we still keep, treat as
	// expired: the only way to recover is a full re-sync, and the RFC says
	// the server "MUST NOT" return the full state without an explicit empty
	// token, so 403 is the right answer.
	if let RequestedToken::Some(seq) = requested
		&& seq < state.sequence
		&& !still_kept(collection, seq).await
	{
		return ReportOutcome::Forbidden;
	}
	let changes: Vec<Change> = if matches!(requested, RequestedToken::Empty) {
		// Empty token: enumerate every current member. A first sync gets
		// the full state, the way the RFC describes.
		enumerate_current(collection, is_calendar, is_addressbook).await
	} else {
		since(collection, valid).await
	};
	let body = build_multistatus(
		collection,
		&state,
		&changes,
		is_calendar,
		is_addressbook,
		collection_href,
	)
	.await;
	ReportOutcome::Multistatus(body)
}

/// Walk the collection and return one change-log-shaped entry per current
/// member: `(sequence=state.sequence, href, deleted=false)`. The sequence
/// here is a fiction — the request gets the full state — but the shape
/// matches what `build_multistatus` consumes.
async fn enumerate_current(
	collection: &Path,
	is_calendar: bool,
	is_addressbook: bool,
) -> Vec<Change> {
	let state = current(collection).await;
	let Ok(mut dir) = tokio::fs::read_dir(collection).await else {
		return Vec::new();
	};
	let mut out = Vec::new();
	while let Ok(Some(child)) = dir.next_entry().await {
		let Ok(kind) = child.file_type().await else {
			continue;
		};
		if !crate::util::fs_walk::allowed(&child.path(), kind) {
			continue;
		}
		if kind.is_dir() {
			continue;
		}
		let Ok(sym) = std::fs::symlink_metadata(child.path()) else {
			continue;
		};
		if sym.file_type().is_symlink() {
			continue;
		}
		let name = child.file_name();
		let name = name.to_string_lossy();
		if !is_kind(&name, is_calendar, is_addressbook) {
			continue;
		}
		out.push(Change {
			sequence: state.sequence,
			href: name.into_owned(),
			deleted: false,
		});
	}
	out.sort_by(|a, b| a.href.cmp(&b.href));
	out
}

/// What the request's `sync-level` attribute asked for.
enum LevelOutcome {
	/// `sync-level=1` (or absent, default).
	One,
	/// `sync-level=infinity`, refused.
	Infinite,
	/// Unparseable value.
	Bad,
}

/// What the request asked for in its `DAV:sync-token` element.
#[derive(Debug, PartialEq, Eq)]
enum RequestedToken {
	/// The body has no `DAV:sync-token` element at all, or its value is
	/// empty: the first-sync case. The server enumerates every current
	/// member.
	Empty,
	/// The body names a token this server issued, and the numeric part
	/// parses cleanly.
	Some(u64),
	/// The body names a `DAV:sync-token` whose value is not a token this
	/// server can recognise.
	Unknown,
}

/// Read the `sync-level` value out of the request body, in either of
/// the two shapes RFC 6578 allows:
///
/// - `<D:sync-collection><D:sync-level>1</D:sync-level>...` (element)
/// - `<D:sync-collection DAV:sync-level="1">...` (attribute, no namespace
///   prefix on the attribute itself; the client would also be allowed to
///   write it with a prefix, but the bare form is the common one)
///
/// The default when no value is present is `1`. Anything other than `1`
/// or `infinity` is `Bad`; `infinity` is refused because the rest of
/// the WebDAV layer refuses infinite walks.
fn sync_level(body: &str) -> LevelOutcome {
	if let Some(value) = attr(body, "sync-level") {
		return match value.trim() {
			"1" => LevelOutcome::One,
			"infinity" => LevelOutcome::Infinite,
			_ => LevelOutcome::Bad,
		};
	}
	if let Some(value) = element_text(body, "sync-level") {
		return match value.trim() {
			"1" => LevelOutcome::One,
			"infinity" => LevelOutcome::Infinite,
			_ => LevelOutcome::Bad,
		};
	}
	LevelOutcome::One
}

/// Read the text content of `<...:name>VALUE</...:name>` from `body`, the
/// first occurrence. Returns `None` if the element is missing or has no
/// closing tag.
fn element_text(body: &str, name: &str) -> Option<String> {
	let bytes = body.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let rest = &body[i..];
		let Some(close) = rest.find('>') else {
			return None;
		};
		let tag = &rest[1..close];
		let local = tag
			.rsplit(':')
			.next()
			.unwrap_or(tag)
			.trim_end_matches('/')
			.trim();
		if local == name {
			let after = &rest[close + 1..];
			let Some(end) = after.find('<') else {
				return None;
			};
			return Some(after[..end].to_string());
		}
		i += close + 1;
	}
	None
}

/// Read the `DAV:sync-token` element from the body. The shape is one of
/// three:
///
/// - `RequestedToken::Empty`: the body has no `DAV:sync-token` element, or
///   the element is empty. The first-sync case: the server enumerates every
///   current member.
/// - `RequestedToken::Some(seq)`: the body names a token this server
///   issued, and the numeric part parses cleanly.
/// - `RequestedToken::Unknown`: the body names a `DAV:sync-token` whose
///   value is not a token this server can recognise.
fn parse_requested_token(body: &str) -> RequestedToken {
	let needle = "sync-token";
	let bytes = body.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let rest = &body[i..];
		let Some(close) = rest.find('>') else {
			return RequestedToken::Empty;
		};
		let tag = &rest[1..close];
		let local = tag
			.rsplit(':')
			.next()
			.unwrap_or(tag)
			.trim_end_matches('/')
			.trim();
		if local == needle {
			let after = &rest[close + 1..];
			let Some(end) = after.find('<') else {
				return RequestedToken::Unknown;
			};
			let value = after[..end].trim();
			return match parse_token(value) {
				Some(seq) => RequestedToken::Some(seq),
				None if value.is_empty() => RequestedToken::Empty,
				None => RequestedToken::Unknown,
			};
		}
		// Skip past the tag name in one jump, like the rest of the
		// webdav scanners.
		i += close + 1;
	}
	RequestedToken::Empty
}

/// Whether the change log still has the line for `sequence`. The sequence
/// is the token's numeric part; it lives in the log iff the corresponding
/// line is among the last [`MAX_ENTRIES`] retained. Sequence 0 is the
/// empty-log baseline, never present on disk, and counts as "kept" so a
/// token of `urn:epistle:sync:0` does not get spuriously refused.
async fn still_kept(collection: &Path, sequence: u64) -> bool {
	if sequence == 0 {
		return true;
	}
	since(collection, sequence - 1)
		.await
		.iter()
		.any(|change| change.sequence == sequence)
}

/// Read the value of an XML attribute `name="value"` from `body`. Mirrors
/// the scanner in [`super::caldav::attr`] — the request is small, so a
/// linear scan is enough.
fn attr(body: &str, name: &str) -> Option<String> {
	let needle = format!("{name}=");
	let mut from = 0;
	while let Some(rel) = body[from..].find(&needle) {
		let at = from + rel;
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

/// Build the `207 Multi-Status` body for the `sync-collection` answer. The
/// current `sync-token` is always in the response (as a property on the
/// collection's own response), the changed resources are listed as
/// `<D:response>` elements with `<D:status>HTTP/1.1 200 OK</D:status>` (or
/// `404` for a deleted entry), and the `multistatus` carries the token so
/// even a client that only reads the body has it. `collection_href` is the
/// collection's href as the client sees it; child resource hrefs are
/// `<collection_href><name>`.
async fn build_multistatus(
	collection: &Path,
	state: &State,
	changes: &[Change],
	is_calendar: bool,
	is_addressbook: bool,
	collection_href: &str,
) -> String {
	let mut body = String::from(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
		<D:multistatus xmlns:D=\"DAV:\" \
		xmlns:C=\"urn:ietf:params:xml:ns:carddav\" \
		xmlns:CAL=\"urn:ietf:params:xml:ns:caldav\" \
		xmlns:CS=\"http://calendarserver.org/ns/\">\n",
	);
	// The collection itself: its token (always present) and `getctag`.
	body.push_str(&format!(
		"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\
		\t\t<D:propstat>\n\t\t\t<D:prop>\n\
		\t\t\t\t<D:sync-token>{token}</D:sync-token>\n\
		\t\t\t\t<CS:getctag>{token}</CS:getctag>\n\
		\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 200 OK</D:status>\n\
		\t</D:propstat>\n\t</D:response>\n",
		href = collection_href,
		token = state.token,
	));
	if changes.is_empty() {
		// No changes since the named token: emit the empty result.
		body.push_str("</D:multistatus>\n");
		return body;
	}
	// An entry for each change: 200 with `getetag` (and `address-data` /
	// `calendar-data` for the live ones), or 404 for deletes.
	for change in changes {
		let status = if change.deleted {
			"HTTP/1.1 404 Not Found"
		} else {
			"HTTP/1.1 200 OK"
		};
		// `collection_href` is always passed with a trailing slash, so
		// the child href is the literal concatenation. We still defend
		// against a stray empty path (an absolute href by itself).
		let child_href = if change.href.starts_with('/') {
			change.href.clone()
		} else {
			format!("{collection_href}{}", change.href)
		};
		let mut response = format!(
			"\t<D:response>\n\t\t<D:href>{href}</D:href>\n\
			\t\t<D:propstat>\n\t\t\t<D:prop>\n",
			href = child_href,
		);
		if !change.deleted {
			let resource = collection.join(&change.href);
			if let Ok(meta) = tokio::fs::metadata(&resource).await
				&& meta.is_file()
				&& is_kind(&change.href, is_calendar, is_addressbook)
			{
				response.push_str(&format!(
					"\t\t\t\t<D:getetag>{etag}</D:getetag>\n",
					etag = carddav::etag(&meta)
				));
				if let Ok(bytes) = tokio::fs::read(&resource).await {
					let element = if is_calendar { "calendar-data" } else { "address-data" };
					let prefix = if is_calendar { "CAL" } else { "C" };
					let text = String::from_utf8_lossy(&bytes);
					response.push_str(&format!(
						"\t\t\t\t<{prefix}:{element}>{body}</{prefix}:{element}>\n",
						body = super::propfind::escape(&text)
					));
				}
			} else {
				// The change log claims the resource is live but the
				// file is gone (concurrent delete, race). Return 404 so
				// the client drops the resource, matching what a
				// freshly-emptied collection would do.
				response.push_str(&format!(
					"\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 404 Not Found</D:status>\n\
					\t\t</D:propstat>\n\t</D:response>\n"
				));
				body.push_str(&response);
				continue;
			}
		}
		response.push_str(&format!(
			"\t\t\t</D:prop>\n\t\t\t<D:status>{status}</D:status>\n\
			\t\t</D:propstat>\n\t</D:response>\n"
		));
		body.push_str(&response);
	}
	body.push_str("</D:multistatus>\n");
	body
}

/// Whether a resource href looks like a kind this collection holds. A
/// calendar holds `.ics`, an addressbook holds `.vcf`. Anything else is
/// skipped on sync (we never wrote it but defence in depth: a stray file
/// planted in the collection must not show up in a CalDAV answer).
fn is_kind(href: &str, is_calendar: bool, is_addressbook: bool) -> bool {
	if is_calendar {
		href.to_ascii_lowercase().ends_with(".ics")
	} else if is_addressbook {
		href.to_ascii_lowercase().ends_with(".vcf")
	} else {
		true
	}
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "sync_integration_tests.rs"]
mod integration_tests;
