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
use super::path;
use super::propfind::{self, Entry};

/// The `Allow` header listing every method this server implements.
const ALLOW: &str = "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND";

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

	match request.method().clone() {
		Method::OPTIONS => options(),
		Method::GET => get(&target, true).await,
		Method::HEAD => get(&target, false).await,
		Method::PUT => put(&target, request).await,
		Method::DELETE => delete(&target).await,
		method => dispatch_extension(method.as_str(), &root, &target, &uri_path, request).await,
	}
}

/// Dispatch the WebDAV verbs axum has no `Method` constant for.
async fn dispatch_extension(
	method: &str,
	root: &Path,
	target: &Path,
	uri_path: &str,
	request: Request,
) -> Response {
	match method {
		"MKCOL" => mkcol(target).await,
		"PROPFIND" => propfind(target, uri_path, request.headers()).await,
		"COPY" => copy_move(root, target, request.headers(), false).await,
		"MOVE" => copy_move(root, target, request.headers(), true).await,
		_ => method_not_allowed(),
	}
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

/// `OPTIONS`: advertise WebDAV class 1 and the allowed methods.
fn options() -> Response {
	Response::builder()
		.status(StatusCode::OK)
		.header(header::ALLOW, ALLOW)
		.header("DAV", "1")
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
		.header(header::CONTENT_TYPE, "application/octet-stream")
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

/// `PUT`: create or replace a file. The parent must already exist (RFC 4918
/// §9.7.1 — a `PUT` to a non-existent collection is `409 Conflict`). Returns
/// `201` when the file is new, `204` when it replaced an existing one.
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
	let existed = target.is_file();
	let body = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
		Ok(bytes) => bytes,
		Err(_) => return StatusCode::BAD_REQUEST.into_response(),
	};
	match tokio::fs::write(target, &body).await {
		Ok(()) if existed => StatusCode::NO_CONTENT.into_response(),
		Ok(()) => StatusCode::CREATED.into_response(),
		Err(error) if error.kind() == std::io::ErrorKind::StorageFull => {
			StatusCode::INSUFFICIENT_STORAGE.into_response()
		}
		Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
		Ok(()) => StatusCode::NO_CONTENT.into_response(),
		Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	}
}

/// `MKCOL`: create a single collection. The parent must exist (else `409`) and
/// the target must not (else `405`). Success is `201`.
async fn mkcol(target: &Path) -> Response {
	if target.exists() {
		return StatusCode::METHOD_NOT_ALLOWED.into_response();
	}
	let Some(parent) = target.parent() else {
		return StatusCode::FORBIDDEN.into_response();
	};
	if !parent.is_dir() {
		return StatusCode::CONFLICT.into_response();
	}
	match tokio::fs::create_dir(target).await {
		Ok(()) => StatusCode::CREATED.into_response(),
		Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	}
}

/// `PROPFIND`: a `207` multi-status of the target (and, at `Depth: 1`, its
/// children). `Depth: infinity` is treated as `1` (we do not recurse fully).
async fn propfind(target: &Path, uri_path: &str, headers: &HeaderMap) -> Response {
	let metadata = match tokio::fs::metadata(target).await {
		Ok(metadata) => metadata,
		Err(_) => return StatusCode::NOT_FOUND.into_response(),
	};
	let depth = headers
		.get("Depth")
		.and_then(|value| value.to_str().ok())
		.map(str::trim)
		.unwrap_or("0");
	let mut entries = vec![entry_for(uri_path, &metadata, display_name(uri_path))];
	if depth != "0"
		&& metadata.is_dir()
		&& let Ok(mut dir) = tokio::fs::read_dir(target).await
	{
		let base = uri_path.trim_end_matches('/');
		while let Ok(Some(child)) = dir.next_entry().await {
			let name = child.file_name();
			let name = name.to_string_lossy();
			let Ok(child_meta) = child.metadata().await else {
				continue;
			};
			let href = format!("{base}/{name}");
			entries.push(entry_for(&href, &child_meta, name.to_string()));
		}
	}
	let body = propfind::multistatus(&entries);
	(
		StatusCode::MULTI_STATUS,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		body,
	)
		.into_response()
}

/// Build a PROPFIND [`Entry`] from filesystem metadata. A collection's href is
/// given a trailing slash, as RFC 4918 recommends.
fn entry_for(href: &str, metadata: &std::fs::Metadata, display: String) -> Entry {
	let is_collection = metadata.is_dir();
	let href = if is_collection && !href.ends_with('/') {
		format!("{href}/")
	} else {
		href.to_string()
	};
	Entry {
		href,
		is_collection,
		length: metadata.len(),
		modified: metadata.modified().ok(),
		display_name: display,
	}
}

/// The last non-empty path segment, used as the `displayname`.
fn display_name(uri_path: &str) -> String {
	uri_path
		.trim_end_matches('/')
		.rsplit('/')
		.next()
		.filter(|s| !s.is_empty())
		.unwrap_or("/")
		.to_string()
}

/// `COPY`/`MOVE`: resolve the `Destination` header into the same account tree,
/// honour `Overwrite`, then copy (and, for `MOVE`, remove the source). The
/// destination crossing the account root is impossible — it is resolved through
/// the same confinement as every other path.
async fn copy_move(root: &Path, source: &Path, headers: &HeaderMap, remove: bool) -> Response {
	if !source.exists() {
		return StatusCode::NOT_FOUND.into_response();
	}
	let Some(dest_path) = destination_path(root, headers) else {
		return StatusCode::FORBIDDEN.into_response();
	};
	let overwrite = headers
		.get("Overwrite")
		.and_then(|value| value.to_str().ok())
		.map(|value| !value.eq_ignore_ascii_case("F"))
		.unwrap_or(true);
	let existed = dest_path.exists();
	if existed && !overwrite {
		return StatusCode::PRECONDITION_FAILED.into_response();
	}
	let Some(parent) = dest_path.parent() else {
		return StatusCode::FORBIDDEN.into_response();
	};
	if !parent.is_dir() {
		return StatusCode::CONFLICT.into_response();
	}
	if let Err(response) = perform_copy(source, &dest_path, existed).await {
		return response;
	}
	if remove {
		let removal = if source.is_dir() {
			tokio::fs::remove_dir_all(source).await
		} else {
			tokio::fs::remove_file(source).await
		};
		if removal.is_err() {
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
	}
	if existed {
		StatusCode::NO_CONTENT.into_response()
	} else {
		StatusCode::CREATED.into_response()
	}
}

/// Copy `source` onto `dest`, replacing an existing destination first. A
/// directory source is copied recursively. On error returns the response to
/// send.
async fn perform_copy(source: &Path, dest: &Path, existed: bool) -> Result<(), Response> {
	if existed {
		let removal = if dest.is_dir() {
			tokio::fs::remove_dir_all(dest).await
		} else {
			tokio::fs::remove_file(dest).await
		};
		if removal.is_err() {
			return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
		}
	}
	let result = if source.is_dir() {
		copy_dir(source, dest).await
	} else {
		tokio::fs::copy(source, dest).await.map(|_| ())
	};
	result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Recursively copy a directory tree (an iterative walk; no async recursion).
async fn copy_dir(source: &Path, dest: &Path) -> std::io::Result<()> {
	let mut stack = vec![(source.to_path_buf(), dest.to_path_buf())];
	while let Some((from, to)) = stack.pop() {
		tokio::fs::create_dir_all(&to).await?;
		let mut dir = tokio::fs::read_dir(&from).await?;
		while let Some(child) = dir.next_entry().await? {
			let child_to = to.join(child.file_name());
			if child.file_type().await?.is_dir() {
				stack.push((child.path(), child_to));
			} else {
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

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
