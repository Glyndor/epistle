use super::*;
use crate::webdav::href;
use crate::webdav::propfind::Entry;

/// `PROPFIND`: a `207` multi-status of the target (and, at `Depth: 1`, its
/// children). The spec says a missing `Depth` header means "infinity"
/// (RFC 4918 §9.1) and an infinite walk on an arbitrary per-user
/// tree would be a denial-of-service trap. We refuse any `Depth` of
/// `infinity` (or missing) with `403 Forbidden` carrying the
/// `propfind-finite-depth` precondition; the client can retry with
/// `Depth: 0` or `Depth: 1`.
///
/// A body asking for the CardDAV discovery props
/// (`current-user-principal`/`addressbook-home-set`/`principal-URL`) is answered
/// with the discovery document instead, pointing the client at the account
/// home as its addressbook home.
pub(super) async fn propfind(target: &Path, uri_path: &str, request: Request) -> Response {
	let depth = match request.headers().get("Depth") {
		None => return propfind_finite_depth_precondition(),
		Some(value) => match value.to_str().map(str::trim) {
			Ok("0") => "0",
			Ok("1") => "1",
			Ok(value) if value.eq_ignore_ascii_case("infinity") => {
				return propfind_finite_depth_precondition();
			}
			_ => return StatusCode::BAD_REQUEST.into_response(),
		},
	};
	let Some(encoded_path) = href::canonical(uri_path) else {
		return StatusCode::BAD_REQUEST.into_response();
	};
	let uri_path = encoded_path.as_str();
	let body_bytes = match read_body_capped(request.into_body(), XML_BODY_LIMIT).await {
		Ok(bytes) => bytes,
		Err(response) => return *response,
	};
	if propfind::wants_discovery(&String::from_utf8_lossy(&body_bytes)) {
		return xml_multistatus(propfind::discovery(uri_path, &account_home(uri_path)));
	}
	let metadata = match tokio::fs::metadata(target).await {
		Ok(metadata) => metadata,
		Err(_) => return StatusCode::NOT_FOUND.into_response(),
	};
	let mut entries = vec![entry_for(
		uri_path,
		target,
		&metadata,
		display_name(uri_path),
	)];
	if depth != "0"
		&& metadata.is_dir()
		&& let Ok(mut dir) = tokio::fs::read_dir(target).await
	{
		let base = uri_path.trim_end_matches('/');
		while let Ok(Some(child)) = dir.next_entry().await {
			let Ok(kind) = child.file_type().await else {
				continue;
			};
			if !crate::util::fs_walk::allowed(&child.path(), kind) {
				continue;
			}
			let name = child.file_name();
			let name = name.to_string_lossy();
			// Hide the addressbook/calendar markers from listings , internal flags.
			if name == carddav::MARKER || name == caldav::MARKER {
				continue;
			}
			// Defence in depth: skip a child that is itself a symlink. The
			// dispatch guard already refused a request whose path walked
			// through a symlink, but a symlink at a directory entry (planted
			// directly in the account tree) would still appear in the
			// listing if we did not filter it here. `child.metadata()`
			// follows the symlink, so we also check `symlink_metadata`.
			let Ok(child_sym) = tokio::fs::symlink_metadata(child.path()).await else {
				continue;
			};
			if child_sym.file_type().is_symlink() {
				continue;
			}
			let Ok(child_meta) = child.metadata().await else {
				continue;
			};
			let href = format!("{base}/{}", href::segment(&name));
			entries.push(entry_for(
				&href,
				&child.path(),
				&child_meta,
				name.to_string(),
			));
		}
	}
	xml_multistatus(propfind::multistatus(&entries))
}

/// Answer a `PROPFIND` whose `Depth` is missing or `infinity` with
/// `403 Forbidden` and the `propfind-finite-depth` precondition
/// (RFC 4918 §9.1). A client that sees this can retry with a finite
/// `Depth`.
fn propfind_finite_depth_precondition() -> Response {
	(
		StatusCode::FORBIDDEN,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		concat!(
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
			"<D:error xmlns:D=\"DAV:\">\n",
			"  <D:propfind-finite-depth/>\n",
			"</D:error>\n",
		),
	)
		.into_response()
}

/// Wrap an already-built multi-status XML body in the `207` response.
fn xml_multistatus(body: String) -> Response {
	(
		StatusCode::MULTI_STATUS,
		[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
		body,
	)
		.into_response()
}

/// The addressbook home for a request: the account's root collection, `/<acct>/`
/// , built from the first path segment of the request, or `/` at the root. This
/// is what the discovery props hand back to a client.
fn account_home(uri_path: &str) -> String {
	let first = uri_path
		.trim_start_matches('/')
		.split('/')
		.next()
		.unwrap_or("");
	if first.is_empty() {
		"/".to_string()
	} else {
		format!("/{first}/")
	}
}

/// Build a PROPFIND [`Entry`] from filesystem metadata. A collection's href is
/// given a trailing slash (RFC 4918); an addressbook/calendar collection is
/// flagged so its resourcetype carries `<C:addressbook/>`/`<CAL:calendar/>`; a
/// vCard or iCalendar file carries its content type and an ETag.
fn entry_for(href: &str, disk: &Path, metadata: &std::fs::Metadata, display: String) -> Entry {
	let is_collection = metadata.is_dir();
	let href = if is_collection && !href.ends_with('/') {
		format!("{href}/")
	} else {
		href.to_string()
	};
	Entry {
		href,
		is_collection,
		is_addressbook: is_collection && carddav::is_addressbook(disk),
		is_calendar: is_collection && caldav::is_calendar(disk),
		length: metadata.len(),
		modified: metadata.modified().ok(),
		display_name: display,
		content_type: content_type(disk),
		etag: if is_collection {
			String::new()
		} else {
			carddav::etag(metadata)
		},
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
