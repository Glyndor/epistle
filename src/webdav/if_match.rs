//! The `If-Match` precondition of a WebDAV `PUT`.

use std::path::Path;

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::carddav;

/// RFC 9110 `If-Match` on a PUT: `*` needs an existing resource, a list needs one
/// of its strong tags to equal the current `ETag` (a weak tag never matches).
/// `412` when nothing matches, `400` when the header is not a tag list.
pub(super) fn refusal(headers: &HeaderMap, target: &Path, existed: bool) -> Option<Response> {
	let value = headers
		.get(header::IF_MATCH)?
		.to_str()
		.ok()
		.unwrap_or("\u{0}");
	let value = value.trim();
	if value == "*" {
		return (!existed).then(|| StatusCode::PRECONDITION_FAILED.into_response());
	}
	let mut tags = Vec::new();
	for part in value.split(',') {
		let tag = part.trim();
		let strong = tag.strip_prefix("W/").is_none();
		let quoted = tag.strip_prefix("W/").unwrap_or(tag);
		if quoted.len() < 2 || !quoted.starts_with('"') || !quoted.ends_with('"') {
			return Some(StatusCode::BAD_REQUEST.into_response());
		}
		if strong {
			tags.push(quoted);
		}
	}
	let current = std::fs::metadata(target).ok().map(|m| carddav::etag(&m));
	match current {
		Some(current) if tags.contains(&current.as_str()) => None,
		_ => Some(StatusCode::PRECONDITION_FAILED.into_response()),
	}
}
