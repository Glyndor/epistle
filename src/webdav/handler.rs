//! Method dispatch and the per-method WebDAV handlers (RFC 4918).
//!
//! axum's `MethodFilter` does not cover the WebDAV verbs (`PROPFIND`, `MKCOL`,
//! `COPY`, `MOVE`), so the router installs a single catch-all that lands here:
//! [`dispatch`] authenticates, then branches on `request.method().as_str()`.
//! Each branch resolves the request path into the account's confined tree
//! (`path::resolve`) before touching the filesystem, so traversal is impossible
//! and one account can never reach another's files.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::WebDavState;
use super::auth::{self, REALM};
use super::caldav;
use super::carddav;
use super::path;
use super::propfind;

#[path = "handler_propfind.rs"]
mod propfind_handler;
use propfind_handler::propfind;

/// The `Allow` header listing every method this server implements.
const ALLOW: &str = "OPTIONS, GET, HEAD, POST, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, REPORT";

/// Maximum size of an XML body the server is willing to fully buffer
/// before refusing with `413 Payload Too Large`. The cap covers PROPFIND,
/// REPORT, PROPPATCH, MKCOL and the scheduling Outbox `POST`, all of
/// them are XML-ish bodies that a misbehaving or malicious client could
/// try to blow up to gigabytes. 1 MiB is comfortably larger than any
/// real property listing a CardDAV or CalDAV client will ever produce,
/// and small enough that a request can be rejected without buffering the
/// whole thing.
const XML_BODY_LIMIT: usize = 1024 * 1024;

/// Maximum size of a single `PUT` body. No project-level upload cap was
/// already wired into the WebDAV path, so this constant is the per-file
/// limit. The value mirrors JMAP's advertised `maxSizeUpload` (see
/// [`crate::api::jmap::MAX_UPLOAD_SIZE`]) so the two protocols agree on
/// the per-resource size an authenticated client can write. A per-account
/// storage quota (the `quota_bytes` field in the account config) still
/// applies on top of this for cumulative usage; this is the per-file cap.
const PUT_BODY_LIMIT: usize = 50 * 1024 * 1024;

/// Entry point for every WebDAV request. Authenticates, then dispatches on the
/// method into the account's confined tree. Unknown methods are `405`.
pub async fn dispatch(State(state): State<WebDavState>, request: Request) -> Response {
	let Some(account) = auth::authenticate(request.headers(), &state.directory) else {
		return challenge();
	};
	let Some(root) = path::account_root(&state.data_dir, &account) else {
		return StatusCode::FORBIDDEN.into_response();
	};
	// The account's root collection always exists once it authenticates; create
	// it lazily so the first request to a fresh account is not a 409.
	if tokio::fs::create_dir_all(&root).await.is_err() {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}
	let uri_path = request.uri().path().to_string();
	let Some(target) = path::resolve(&root, &uri_path) else {
		return StatusCode::FORBIDDEN.into_response();
	};
	// A symlink anywhere along the path is an escape attempt: refuse before
	// any I/O. Methods that read or operate on an existing target require
	// the target's canonical form to fall under the canonical root, with no
	// symlink in between; write-create methods require the parent's
	// canonical form to be a real, symlink-free directory under the
	// canonical root.
	if !symlink_check_ok(&target, &root, request.method().as_str()) {
		return StatusCode::FORBIDDEN.into_response();
	}

	match request.method().clone() {
		Method::OPTIONS => options(),
		Method::GET => get(&target, true).await,
		Method::HEAD => get(&target, false).await,
		Method::POST => post(&root, &uri_path, request).await,
		Method::PUT => put(&target, request).await,
		Method::DELETE => delete(&target).await,
		method => dispatch_extension(method.as_str(), &root, &target, &uri_path, request).await,
	}
}

/// Symlink refusal for the dispatch boundary. `GET`/`HEAD`/`DELETE`/
/// `PROPFIND`/`REPORT`/`COPY` (source)/`MOVE` (source) all touch an
/// existing target, so the canonical form must lie under the canonical root
/// with no symlink in between. `PUT`/`MKCOL` create a target, so the
/// parent must be a real, symlink-free directory under the canonical root.
/// `POST` hits a virtual path (the Outbox, which may not exist on disk) so
/// it uses the write-creating rule. `OPTIONS` answers from headers and never
/// touches the filesystem; the lexical [`path::resolve`] it has already
/// passed through covers the rest. Unknown methods (which become a `405`
/// reply) do not need any filesystem access.
///
/// A missing target for a read method (e.g. `GET /missing.txt`) passes
/// confinement as well: there is nothing to follow, so no escape to refuse.
/// The handler still turns that into a `404` for the client.
fn symlink_check_ok(target: &Path, root: &Path, method: &str) -> bool {
	match method {
		"PUT" | "MKCOL" | "POST" => path::confine_parent_for_write(target, root),
		"OPTIONS" => true,
		// Methods handled outside this enum ("PROPFIND", "MKCOL", "REPORT",
		// "COPY", "MOVE") all touch an existing target. Anything else is a
		// `405` reply without filesystem access, so skip the check.
		"PROPFIND" | "REPORT" | "COPY" | "MOVE" | "GET" | "HEAD" | "DELETE" => {
			path::confine_existing(target, root)
		}
		_ => true,
	}
}

/// Dispatch the WebDAV verbs axum has no `Method` constant for, including the
/// CardDAV `REPORT`.
async fn dispatch_extension(
	method: &str,
	root: &Path,
	target: &Path,
	uri_path: &str,
	request: Request,
) -> Response {
	match method {
		"MKCOL" => mkcol(target, request).await,
		"PROPFIND" => propfind(target, uri_path, request).await,
		"REPORT" => report(root, target, uri_path, request).await,
		"COPY" => copy_move(root, target, request.headers(), false).await,
		"MOVE" => copy_move(root, target, request.headers(), true).await,
		_ => method_not_allowed(),
	}
}

/// Read a request body with an explicit byte cap. Returns `413 Payload Too
/// Large` once the cap is exceeded (a body at exactly the cap is accepted,
/// one byte over is not). `axum::body::to_bytes` already stops reading at
/// `limit` bytes, so an oversize body is rejected without the rest of the
/// stream being drained into memory.
///
/// The error is boxed to keep the `Result` small, a full `Response`
/// carries the body bytes in a few code paths and would blow up the
/// stack frame of every caller.
async fn read_body_capped(
	body: axum::body::Body,
	limit: usize,
) -> Result<axum::body::Bytes, Box<Response>> {
	match axum::body::to_bytes(body, limit + 1).await {
		Ok(bytes) if bytes.len() > limit => {
			Err(Box::new(StatusCode::PAYLOAD_TOO_LARGE.into_response()))
		}
		Ok(bytes) => Ok(bytes),
		// `axum::body::to_bytes` returns an error on stream-level failures
		// including the `LengthLimitError` from `http_body_util` (the body
		// exceeded the cap and the inner stream refused more data) and
		// genuine transport failures. Both are reported as `413`: a
		// transport failure on an oversize body looks the same to the
		// client (the body could not be buffered). Other transport errors
		// are also `413` because the request is otherwise unprocessable
		// without a body.
		Err(_) => Err(Box::new(StatusCode::PAYLOAD_TOO_LARGE.into_response())),
	}
}

/// `REPORT` (RFC 6352 / RFC 4791): read the body and hand it to the right
/// report dispatcher. The choice is made by peeking the body's root element: a
/// body naming a CalDAV report (`calendar-multiget`/`calendar-query`/
/// `free-busy-query`) goes to the CalDAV handler, everything else to CardDAV.
/// A body naming `sync-collection` (RFC 6578) is handled by [`super::sync`]
/// once the target collection is known: a calendar for a CalDAV report, an
/// addressbook for CardDAV. The sync handler enforces per-account
/// confinement through the same `target` path the rest of the report
/// dispatchers see.
async fn report(root: &Path, target: &Path, uri_path: &str, request: Request) -> Response {
	let body = match read_body_capped(request.into_body(), XML_BODY_LIMIT).await {
		Ok(bytes) => bytes,
		Err(response) => return *response,
	};
	let text = String::from_utf8_lossy(&body);
	if super::sync::is_sync_collection(&text) {
		return sync_collection_report(target, uri_path, &text).await;
	}
	if caldav::is_caldav_report(&text) {
		caldav::report(root, target, &body).await
	} else {
		carddav::report(root, target, &body).await
	}
}

/// Dispatch a `sync-collection` REPORT against `target`. The target must
/// be a calendar or an addressbook; other collections (and the account
/// root) get `403` with the `DAV:valid-sync-token` precondition, mirroring
/// the RFC's shape for a server that does not support sync on a given
/// collection.
async fn sync_collection_report(target: &Path, uri_path: &str, body: &str) -> Response {
	let is_calendar = caldav::is_calendar(target);
	let is_addressbook = carddav::is_addressbook(target);
	if !is_calendar && !is_addressbook {
		return super::sync::invalid_token_response();
	}
	let collection_href = canonical_collection_href(uri_path);
	match super::sync::handle_report(target, body, is_calendar, is_addressbook, &collection_href)
		.await
	{
		super::sync::ReportOutcome::Multistatus(body) => (
			StatusCode::MULTI_STATUS,
			[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
			body,
		)
			.into_response(),
		super::sync::ReportOutcome::Forbidden => super::sync::invalid_token_response(),
	}
}

/// Build the collection's own href as the client sees it: a normalised
/// version of `uri_path` with a trailing slash. The multistatus answers
/// reference each child as `collection_href + name`, so this is the
/// prefix the client gets back.
fn canonical_collection_href(uri_path: &str) -> String {
	let trimmed = uri_path.trim_end_matches('/');
	if trimmed.is_empty() {
		"/".to_string()
	} else {
		format!("{trimmed}/")
	}
}

/// `POST` (RFC 6638 §6.1): a scheduling Outbox free-busy request. Only a POST to
/// the account's conventional `outbox/` path is honoured — it returns the
/// authenticated account's own free/busy, scanning every calendar under the
/// account root (the same `root` that confines every other request). A POST
/// anywhere else is `405`.
async fn post(root: &Path, uri_path: &str, request: Request) -> Response {
	let first = uri_path
		.trim_start_matches('/')
		.split('/')
		.next()
		.unwrap_or("");
	let second = uri_path
		.trim_start_matches('/')
		.split('/')
		.nth(1)
		.unwrap_or("");
	// The Outbox may be at `/<account>/outbox/` or, at the account root, `/outbox/`.
	if first != caldav::OUTBOX && second != caldav::OUTBOX {
		return method_not_allowed();
	}
	let body = match read_body_capped(request.into_body(), XML_BODY_LIMIT).await {
		Ok(bytes) => bytes,
		Err(response) => return *response,
	};
	caldav::outbox_post(root, &body).await
}

/// `401` with the Basic challenge so clients prompt for credentials.
fn challenge() -> Response {
	(
		StatusCode::UNAUTHORIZED,
		[(header::WWW_AUTHENTICATE, format!("Basic realm=\"{REALM}\""))],
	)
		.into_response()
}

/// `405` advertising the allowed methods.
fn method_not_allowed() -> Response {
	(StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, ALLOW)]).into_response()
}

/// `OPTIONS`: advertise WebDAV class 1 and 3 plus the CardDAV `addressbook`
/// (RFC 6352 §6.1) and CalDAV `calendar-access` (RFC 4791 §5.1) compliance
/// classes — the classes a CardDAV/CalDAV client looks for to know the server
/// speaks each protocol — and the allowed methods. Both are advertised on every
/// resource: it costs nothing and lets a client probe the root before it has
/// found an addressbook or calendar collection.
fn options() -> Response {
	Response::builder()
		.status(StatusCode::OK)
		.header(header::ALLOW, ALLOW)
		.header("DAV", "1, 3, addressbook, calendar-access")
		.body(Body::empty())
		.expect("options response")
}

/// `GET`/`HEAD`: stream a file's bytes (or just its headers when `with_body` is
/// false). A directory or a missing file is `404` (we do not serve listings).
async fn get(target: &Path, with_body: bool) -> Response {
	let metadata = match tokio::fs::metadata(target).await {
		Ok(metadata) if metadata.is_file() => metadata,
		_ => return StatusCode::NOT_FOUND.into_response(),
	};
	let length = metadata.len();
	let modified = metadata.modified().ok();
	let mut builder = Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, content_type(target))
		.header(header::ETAG, carddav::etag(&metadata))
		.header(header::CONTENT_LENGTH, length);
	if let Some(modified) = modified {
		builder = builder.header(header::LAST_MODIFIED, propfind::httpdate(modified));
	}
	if !with_body {
		return builder.body(Body::empty()).expect("head response");
	}
	match tokio::fs::read(target).await {
		Ok(bytes) => builder.body(Body::from(bytes)).expect("get response"),
		Err(_) => StatusCode::NOT_FOUND.into_response(),
	}
}

/// The `Content-Type` for a resource by extension: `text/vcard` for a vCard
/// (`.vcf`, CardDAV), `text/calendar` for an iCalendar object (`.ics`, CalDAV),
/// `application/octet-stream` otherwise.
fn content_type(target: &Path) -> &'static str {
	match target.extension().and_then(|ext| ext.to_str()) {
		Some(ext) if ext.eq_ignore_ascii_case("vcf") => carddav::VCARD_TYPE,
		Some(ext) if ext.eq_ignore_ascii_case("ics") => caldav::CALENDAR_TYPE,
		_ => "application/octet-stream",
	}
}

/// `PUT`: create or replace a file. The parent must already exist (RFC 4918
/// §9.7.1 — a `PUT` to a non-existent collection is `409 Conflict`). Returns
/// `201` when the file is new, `204` when it replaced an existing one, each with
/// the new resource's `ETag` so a CardDAV client can track the card.
///
/// If the target is an existing symlink (escape planted in the user's tree)
/// the request is refused with `403`, `tokio::fs::write` would otherwise
/// follow the link and rewrite the file it points at.
async fn put(target: &Path, request: Request) -> Response {
	if target.is_dir() {
		return StatusCode::METHOD_NOT_ALLOWED.into_response();
	}
	let Some(parent) = target.parent() else {
		return StatusCode::FORBIDDEN.into_response();
	};
	if !parent.is_dir() {
		return StatusCode::CONFLICT.into_response();
	}
	if let Ok(meta) = tokio::fs::symlink_metadata(target).await
		&& meta.file_type().is_symlink()
	{
		return StatusCode::FORBIDDEN.into_response();
	}
	let existed = target.is_file();
	let body = match read_body_capped(request.into_body(), PUT_BODY_LIMIT).await {
		Ok(bytes) => bytes,
		Err(response) => return *response,
	};
	let result = tokio::fs::write(target, &body).await;
	match result {
		Ok(()) => {
			// Record the change in the parent collection's change log so a
			// `sync-collection` REPORT can see the new version. Only record
			// when the parent is a calendar or addressbook; the rest of the
			// WebDAV tree (loose files) has no log.
			if let Some(relative) = resource_relative(parent, target)
				&& (caldav::is_calendar(parent) || carddav::is_addressbook(parent))
			{
				super::sync::record(parent, &relative, false).await;
			}
			put_success(target, existed).await
		}
		Err(error) if error.kind() == std::io::ErrorKind::StorageFull => {
			StatusCode::INSUFFICIENT_STORAGE.into_response()
		}
		Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	}
}

/// The path of `target` relative to `parent`, with forward slashes, ready
/// to be the `href` half of a change-log line. Returns `None` if `target`
/// is not under `parent` (which the dispatch guard already prevented, but
/// failing closed here is correct).
fn resource_relative(parent: &Path, target: &Path) -> Option<String> {
	let rel = target.strip_prefix(parent).ok()?;
	let mut out = String::new();
	for component in rel.components() {
		let std::path::Component::Normal(name) = component else {
			return None;
		};
		if !out.is_empty() {
			out.push('/');
		}
		out.push_str(&name.to_string_lossy());
	}
	Some(out)
}

/// Build the success response for a completed `PUT`: `204`/`201` carrying the
/// freshly written resource's `ETag` (best-effort — omitted if the stat fails).
async fn put_success(target: &Path, existed: bool) -> Response {
	let status = if existed {
		StatusCode::NO_CONTENT
	} else {
		StatusCode::CREATED
	};
	match tokio::fs::metadata(target).await {
		Ok(metadata) => (status, [(header::ETAG, carddav::etag(&metadata))]).into_response(),
		Err(_) => status.into_response(),
	}
}

/// `DELETE`: remove a file or a collection (recursively). Missing is `404`,
/// success is `204`.
async fn delete(target: &Path) -> Response {
	let metadata = match tokio::fs::symlink_metadata(target).await {
		Ok(metadata) => metadata,
		Err(_) => return StatusCode::NOT_FOUND.into_response(),
	};
	let result = if metadata.is_dir() {
		tokio::fs::remove_dir_all(target).await
	} else {
		tokio::fs::remove_file(target).await
	};
	match result {
		Ok(()) => {
			// Record the deletion in the parent collection's change log so a
			// `sync-collection` REPORT can return `404` for the href. For a
			// collection delete we record every file we are about to remove
			// under the collection's parent: each child becomes a `deleted`
			// entry. For a single-file delete, one entry is enough.
			if metadata.is_dir() {
				if let Some(parent) = target.parent() {
					let entries = collect_child_hrefs(target);
					if caldav::is_calendar(parent) || carddav::is_addressbook(parent) {
						let entries: Vec<(String, bool)> =
							entries.into_iter().map(|href| (href, true)).collect();
						super::sync::record_many(parent, &entries).await;
					}
				}
			} else if let Some(parent) = target.parent()
				&& let Some(relative) = resource_relative(parent, target)
				&& (caldav::is_calendar(parent) || carddav::is_addressbook(parent))
			{
				super::sync::record(parent, &relative, true).await;
			}
			StatusCode::NO_CONTENT.into_response()
		}
		Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	}
}

/// Collect every `.ics` or `.vcf` href (relative to `dir`) of a directory
/// the server is about to delete. Used to populate the change log so a
/// sync-collection REPORT for the parent still knows the children are
/// gone. Other file kinds are ignored — only the kind the collection is
/// supposed to hold can land in the log.
fn collect_child_hrefs(dir: &Path) -> Vec<String> {
	let mut out = Vec::new();
	let Ok(mut entries) = std::fs::read_dir(dir) else {
		return out;
	};
	while let Some(Ok(child)) = entries.next() {
		let Ok(kind) = child.file_type() else {
			continue;
		};
		if kind.is_dir() {
			continue;
		}
		let name = child.file_name();
		let name = name.to_string_lossy();
		let lower = name.to_ascii_lowercase();
		if lower.ends_with(".ics") || lower.ends_with(".vcf") {
			out.push(name.into_owned());
		}
	}
	out.sort();
	out
}

/// `MKCOL` (RFC 4918) and extended-MKCOL (RFC 5689): create a single
/// collection. The parent must exist (else `409`) and the target must not (else
/// `405`). When the request body requests the CardDAV `addressbook` or the
/// CalDAV `calendar` resourcetype, the new collection is also flagged
/// accordingly (a [`carddav::MARKER`]/[`caldav::MARKER`] file is written into
/// it). `addressbook` takes precedence if a body somehow names both. Success is
/// `201`.
async fn mkcol(target: &Path, request: Request) -> Response {
	// Use `symlink_metadata` so a target that already exists as a symlink
	// is detected without following the link; refusing here closes a
	// symlink-to-outside edge the dispatch guard (write-creating method)
	// does not check.
	if let Some(meta) = tokio::fs::symlink_metadata(target).await.ok()
		&& (meta.file_type().is_symlink() || meta.is_dir() || meta.is_file())
	{
		return StatusCode::METHOD_NOT_ALLOWED.into_response();
	}
	let Some(parent) = target.parent() else {
		return StatusCode::FORBIDDEN.into_response();
	};
	if !parent.is_dir() {
		return StatusCode::CONFLICT.into_response();
	}
	let body = match read_body_capped(request.into_body(), XML_BODY_LIMIT).await {
		Ok(bytes) => bytes,
		Err(response) => return *response,
	};
	let text = String::from_utf8_lossy(&body);
	let as_addressbook = text.contains("addressbook");
	let as_calendar = !as_addressbook && caldav::requests_calendar(&text);
	if tokio::fs::create_dir(target).await.is_err() {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}
	if as_addressbook && !carddav::mark_addressbook(target).await {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}
	if as_calendar && !caldav::mark_calendar(target).await {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}
	StatusCode::CREATED.into_response()
}

/// `COPY`/`MOVE`: resolve the `Destination` header into the same account tree,
/// honour `Overwrite`, then copy (and, for `MOVE`, remove the source). The
/// destination crossing the account root is impossible — it is resolved through
/// the same confinement as every other path. An overlap (destination equal to
/// or inside the source, or vice versa) is also refused up front: removing
/// the destination first would otherwise destroy data the copy itself needs
/// (RFC 4918 §9.8.5 / §9.9.4).
async fn copy_move(root: &Path, source: &Path, headers: &HeaderMap, remove: bool) -> Response {
	// Use `symlink_metadata` everywhere so the final-component symlink is not
	// followed here; the dispatch-level guard above already confined the
	// source path under `root` and refused any intermediate symlink.
	let source_meta = match tokio::fs::symlink_metadata(source).await {
		Ok(meta) => meta,
		Err(_) => return StatusCode::NOT_FOUND.into_response(),
	};
	if source_meta.file_type().is_symlink() {
		return StatusCode::FORBIDDEN.into_response();
	}
	let Some(dest_path) = destination_path(root, headers) else {
		return StatusCode::FORBIDDEN.into_response();
	};
	// RFC 4918 §9.8.5 / §9.9.4, copying or moving a collection into itself
	// (or onto itself) would lose data: the existing implementation removes
	// the destination before the source is read. Detect any overlap before
	// any I/O and refuse with `403 Forbidden` (a copy or move into a
	// sub-tree of itself is forbidden by RFC 4918).
	if paths_overlap(source, &dest_path) {
		return StatusCode::FORBIDDEN.into_response();
	}
	// Confine the destination with the write-create rule (parent chain is
	// symlink-free and under canonical root). If the destination exists
	// already it has to be confined as well, both because the recursion may
	// replace it and because it could itself be a symlink to outside.
	if !path::confine_parent_for_write(&dest_path, root) {
		return StatusCode::FORBIDDEN.into_response();
	}
	let overwrite = headers
		.get("Overwrite")
		.and_then(|value| value.to_str().ok())
		.map(|value| !value.eq_ignore_ascii_case("F"))
		.unwrap_or(true);
	let dest_meta = tokio::fs::symlink_metadata(&dest_path).await.ok();
	if dest_meta.is_some() && !overwrite {
		return StatusCode::PRECONDITION_FAILED.into_response();
	}
	let Some(parent) = dest_path.parent() else {
		return StatusCode::FORBIDDEN.into_response();
	};
	let parent_meta = match tokio::fs::symlink_metadata(parent).await {
		Ok(meta) => meta,
		Err(_) => return StatusCode::CONFLICT.into_response(),
	};
	if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
		return StatusCode::CONFLICT.into_response();
	}
	let dest_was_dir = dest_meta.as_ref().map(|meta| meta.is_dir());
	let dest_existed = dest_meta.is_some();
	if let Err(response) = perform_copy(source, &dest_path, dest_was_dir).await {
		return *response;
	}
	// Record the destination-side changes: a fresh resource lands in the
	// destination's parent. The destination parent may itself be a calendar
	// or addressbook (the common case for a WebDAV client); if it is
	// neither, the change log is a no-op.
	if let Some(dest_parent) = dest_path.parent() {
		let dest_relative = resource_relative(dest_parent, &dest_path);
		if let Some(relative) = dest_relative
			&& (caldav::is_calendar(dest_parent) || carddav::is_addressbook(dest_parent))
		{
			super::sync::record(dest_parent, &relative, false).await;
		}
	}
	// For `MOVE`, the source side is gone: log every href that disappeared
	// from the source's parent. A file MOVE is one entry; a collection MOVE
	// is one per child.
	if remove {
		if let Some(source_parent) = source.parent() {
			let source_entries: Vec<String> = if source_meta.is_dir() {
				collect_child_hrefs(source)
			} else if let Some(rel) = resource_relative(source_parent, source) {
				vec![rel]
			} else {
				Vec::new()
			};
			if !source_entries.is_empty()
				&& (caldav::is_calendar(source_parent) || carddav::is_addressbook(source_parent))
			{
				let entries: Vec<(String, bool)> = source_entries
					.into_iter()
					.map(|href| (href, true))
					.collect();
				super::sync::record_many(source_parent, &entries).await;
			}
		}
		let removal = if source_meta.is_dir() {
			tokio::fs::remove_dir_all(source).await
		} else {
			tokio::fs::remove_file(source).await
		};
		if removal.is_err() {
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	}
	if dest_existed {
		StatusCode::NO_CONTENT.into_response()
	} else {
		StatusCode::CREATED.into_response()
	}
}

/// Copy `source` onto `dest`, replacing an existing destination first. A
/// directory source is copied recursively; any child that is itself a
/// symlink is skipped (we do not follow external links into the destination
/// tree). On error returns the response to send.
async fn perform_copy(
	source: &Path,
	dest: &Path,
	dest_was_dir: Option<bool>,
) -> Result<(), Box<Response>> {
	if let Some(is_dir) = dest_was_dir {
		// Remove the destination without ever following a symlink: we
		// already know the destination's existence and kind from the
		// `symlink_metadata` gathered by the caller, which never resolves
		// the link.
		let removal = if is_dir {
			tokio::fs::remove_dir_all(dest).await
		} else {
			tokio::fs::remove_file(dest).await
		};
		if removal.is_err() {
			return Err(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()));
		}
	}
	let result = if source.is_dir() {
		copy_dir(source, dest).await
	} else {
		tokio::fs::copy(source, dest).await.map(|_| ())
	};
	result.map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

/// Recursively copy a directory tree (an iterative walk; no async recursion).
/// Any child that is itself a symlink is skipped: we never follow the link
/// into the destination tree.
async fn copy_dir(source: &Path, dest: &Path) -> std::io::Result<()> {
	let mut stack = vec![(source.to_path_buf(), dest.to_path_buf())];
	while let Some((from, to)) = stack.pop() {
		tokio::fs::create_dir_all(&to).await?;
		let mut dir = tokio::fs::read_dir(&from).await?;
		while let Some(child) = dir.next_entry().await? {
			let file_type = child.file_type().await?;
			if !crate::util::fs_walk::allowed(&child.path(), file_type) {
				continue;
			}
			let child_to = to.join(child.file_name());
			if file_type.is_dir() {
				stack.push((child.path(), child_to));
			} else if file_type.is_file() {
				tokio::fs::copy(child.path(), &child_to).await?;
			}
		}
	}
	Ok(())
}

/// Resolve the `Destination` header — an absolute URL or an absolute path —
/// into a confined on-disk path under the same account `root`. `None` if it is
/// missing, malformed, or would escape the root (fail closed).
fn destination_path(root: &Path, headers: &HeaderMap) -> Option<PathBuf> {
	let raw = headers.get("Destination")?.to_str().ok()?;
	let dest_path = strip_to_path(raw);
	path::resolve(root, dest_path)
}

/// Reduce a `Destination` value to its absolute path component, stripping a
/// `scheme://authority` prefix when present.
fn strip_to_path(raw: &str) -> &str {
	if let Some(rest) = raw.find("://").map(|i| &raw[i + 3..]) {
		match rest.find('/') {
			Some(slash) => &rest[slash..],
			None => "/",
		}
	} else {
		raw
	}
}

/// Whether two paths occupy the same place or one sits inside the other.
/// A `MOVE /a /a` is an exact match; a `MOVE /a /a/b` or `MOVE /a/b /a` is
/// an ancestor/descendant relationship. The check is the same for files and
/// directories, the per-method handler does not need to know the kind.
/// Comparing lexical paths is sufficient here: both names were resolved
/// through the same per-account `path::resolve` so a path that does not
/// share a prefix with the other could not have been conflated.
fn paths_overlap(a: &Path, b: &Path) -> bool {
	if a == b {
		return true;
	}
	// Path components give a robust boundary match: `/a/b` and `/a/b/c`
	// share the first two components, while `/a/bc` does not share a third.
	let a_comps: Vec<_> = a.components().collect();
	let b_comps: Vec<_> = b.components().collect();
	b_comps.starts_with(&a_comps) || a_comps.starts_with(&b_comps)
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "handler_bounds_tests.rs"]
mod bounds_tests;
