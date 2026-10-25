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
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::WebDavState;
use super::auth::{self, REALM};
use super::bounds;
use super::caldav;
use super::carddav;
use super::path;
use super::propfind;
use super::quota::{Change, LOG_RESERVE, MIN_ENTRY_BYTES, Quota};
use super::report_bounds::MAX_RESOURCE_BYTES;

#[path = "handler_propfind.rs"]
mod propfind_handler;
use propfind_handler::propfind;
#[path = "handler_copy.rs"]
mod copy_handler;
#[path = "handler_sync.rs"]
mod sync_handler;
use copy_handler::copy_move;

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
/// limit. It was chosen to match the old fixed JMAP upload limit; JMAP now
/// follows `[server] max_message_size` (25 MiB by default), so a DAV
/// resource may be larger than a message. A per-account
/// storage quota (the `quota_bytes` field in the account config) applies on
/// top of this for cumulative usage; this is the per-file cap.
///
/// WebDAV `PUT` keeps its own cap rather than `[server] max_message_size`
/// because a single resource (a calendar, a long vCard, a large attachment
/// archive) can be larger than a single mail message by design. The cap is
/// fixed at `PUT_BODY_LIMIT` and is **not** configurable from
/// `epistle limits set`: an Internet standard does not require a specific
/// size for a DAV resource, only that the server advertises the limit it
/// will accept.
///
/// A `.ics` or `.vcf` is held to [`MAX_RESOURCE_BYTES`] instead, the most a
/// report can always hand back on its own.
const PUT_BODY_LIMIT: usize = 50 * 1024 * 1024;

/// Entry point for every WebDAV request. Authenticates, then dispatches on the
/// method into the account's confined tree. Unknown methods are `405`.
pub async fn dispatch(State(state): State<WebDavState>, request: Request) -> Response {
	let peer = request
		.extensions()
		.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
		.map(|info| crate::net::canonical_peer(info.0));
	// Resolve the client address through the same trusted-proxy chain the
	// API listeners use (`X-Forwarded-For`, walking from the right, fails
	// closed on a malformed entry). Behind a trusted reverse proxy the
	// failure audit log and the per-IP ban counters key on the real
	// client; without one they key on the socket peer like the API does.
	let peer = peer.and_then(|socket| {
		crate::net::trusted_ip::effective(&state.trusted_proxies, Some(socket), request.headers())
	});
	let Some(account) = auth::authenticate(request.headers(), &state.directory, peer) else {
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
	let quota = Quota::new(&state, &account, &root);
	let uri_path = request.uri().path().to_string();
	// A name with a control character cannot be created any more, but one
	// made earlier can still be removed or moved away.
	let legacy_name =
		path::has_control_char(&uri_path) && matches!(request.method().as_str(), "DELETE" | "MOVE");
	if path::has_control_char(&uri_path) && !legacy_name {
		return StatusCode::BAD_REQUEST.into_response();
	}
	let Some(target) = (if legacy_name {
		path::resolve_existing(&root, &uri_path)
	} else {
		path::resolve(&root, &uri_path)
	}) else {
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
	if sync_handler::is_reserved(&target) {
		return StatusCode::NOT_FOUND.into_response();
	}

	match request.method().clone() {
		Method::OPTIONS => options(),
		Method::GET => get(&target, true).await,
		Method::HEAD => get(&target, false).await,
		Method::POST => post(&root, &uri_path, request).await,
		Method::PUT => put(&target, &quota, request).await,
		Method::DELETE => delete(&target, &quota).await,
		method => {
			dispatch_extension(method.as_str(), &root, &target, &uri_path, &quota, request).await
		}
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
	quota: &Quota,
	request: Request,
) -> Response {
	match method {
		"MKCOL" => mkcol(target, quota, request).await,
		"PROPFIND" => propfind(target, uri_path, request).await,
		"REPORT" => report(root, target, request).await,
		"COPY" => copy_move(root, target, request.headers(), false, quota).await,
		"MOVE" => copy_move(root, target, request.headers(), true, quota).await,
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

/// `REPORT` (RFC 6352 / RFC 4791 / RFC 6578): read the body and hand it to
/// the right report dispatcher, chosen by the body's root element: a
/// `sync-collection` goes to [`sync_handler`], a CalDAV report
/// (`calendar-multiget`/`calendar-query`/`free-busy-query`) to the CalDAV
/// handler, everything else to CardDAV. All of them build hrefs from the same
/// confined `root` and `target`.
async fn report(root: &Path, target: &Path, request: Request) -> Response {
	let (parts, body) = request.into_parts();
	let body = match read_body_capped(body, XML_BODY_LIMIT).await {
		Ok(bytes) => bytes,
		Err(response) => return *response,
	};
	let text = String::from_utf8_lossy(&body);
	if super::sync_report::is_sync_collection(&text) {
		return sync_handler::report(root, target, &parts.headers, &text).await;
	}
	if caldav::is_caldav_report(&text) {
		caldav::report(root, target, &body).await
	} else {
		carddav::report(root, target, &body).await
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
async fn put(target: &Path, quota: &Quota, request: Request) -> Response {
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
	let limit =
		if caldav::is_ics_path(&uri_name(target)) || carddav::is_vcard_path(&uri_name(target)) {
			MAX_RESOURCE_BYTES as usize
		} else {
			PUT_BODY_LIMIT
		};
	let body = match read_body_capped(request.into_body(), limit).await {
		Ok(bytes) => bytes,
		Err(response) => return *response,
	};
	// The size is the real one, the body already read. The reservation holds
	// the account's quota lock until the file is written.
	let mut reservation = match quota
		.admit(Change {
			bytes: (body.len() as u64).max(MIN_ENTRY_BYTES),
			replaces: existed.then(|| target.to_path_buf()),
			..Change::default()
		})
		.await
	{
		Ok(reservation) => reservation,
		Err(response) => return *response,
	};
	if let Err(response) = quota.check_create(target, None).await {
		reservation.invalidate();
		return *response;
	}
	let written = tokio::fs::write(target, &body).await;
	if written.is_err() {
		reservation.invalidate();
		bounds::forget_counts(&[target]);
	}
	match written {
		Ok(()) => {
			sync_handler::log_member(target, false).await;
			put_success(target, existed).await
		}
		Err(error) if error.kind() == std::io::ErrorKind::StorageFull => {
			StatusCode::INSUFFICIENT_STORAGE.into_response()
		}
		Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	}
}

/// The last path component of `target`, for judging its extension.
pub(super) fn uri_name(target: &Path) -> String {
	target
		.file_name()
		.map(|name| name.to_string_lossy().into_owned())
		.unwrap_or_default()
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
async fn delete(target: &Path, quota: &Quota) -> Response {
	let _reservation = quota.exclusive().await;
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
			bounds::forget_counts(&[target]);
			if !metadata.is_dir() {
				sync_handler::log_member(target, true).await;
			}
			StatusCode::NO_CONTENT.into_response()
		}
		Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	}
}

/// `MKCOL` (RFC 4918) and extended-MKCOL (RFC 5689): create a single
/// collection. The parent must exist (else `409`) and the target must not (else
/// `405`). When the request body requests the CardDAV `addressbook` or the
/// CalDAV `calendar` resourcetype, the new collection is also flagged
/// accordingly (a [`carddav::MARKER`]/[`caldav::MARKER`] file is written into
/// it). `addressbook` takes precedence if a body somehow names both. Success is
/// `201`.
async fn mkcol(target: &Path, quota: &Quota, request: Request) -> Response {
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
	// A collection costs its own entry and, when flagged, the marker file in it.
	let flagged = as_addressbook || as_calendar;
	let cost = MIN_ENTRY_BYTES * (1 + u64::from(flagged)) + if flagged { LOG_RESERVE } else { 0 };
	let mut reservation = match quota
		.admit(Change {
			bytes: cost,
			..Change::default()
		})
		.await
	{
		Ok(reservation) => reservation,
		Err(response) => return *response,
	};
	if let Err(response) = quota.check_create(target, None).await {
		reservation.invalidate();
		return *response;
	}
	if tokio::fs::create_dir(target).await.is_err() {
		reservation.invalidate();
		bounds::forget_counts(&[target]);
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

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "handler_lock_tests.rs"]
mod lock_tests;

#[cfg(test)]
#[path = "handler_bounds_tests.rs"]
mod bounds_tests;

#[cfg(test)]
#[path = "handler_trusted_proxy_tests.rs"]
mod trusted_proxy_tests;
