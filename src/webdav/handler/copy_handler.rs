//! `COPY` and `MOVE`: resolving the `Destination`, the checks that go with the
//! account's lock, and the copy itself.

use std::path::{Path, PathBuf};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::super::quota::{Change, Quota};
use super::super::report_bounds::MAX_RESOURCE_BYTES;
use super::super::{caldav, carddav, path};
use super::{bounds, sync_handler, uri_name};

/// `COPY`/`MOVE`: resolve the `Destination` header into the same account tree,
/// honour `Overwrite`, then copy (and, for `MOVE`, remove the source). The
/// destination crossing the account root is impossible — it is resolved through
/// the same confinement as every other path. An overlap (destination equal to
/// or inside the source, or vice versa) is also refused up front: removing
/// the destination first would otherwise destroy data the copy itself needs
/// (RFC 4918 §9.8.5 / §9.9.4).
pub(super) async fn copy_move(
	root: &Path,
	source: &Path,
	headers: &HeaderMap,
	remove: bool,
	quota: &Quota,
) -> Response {
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
	if headers
		.get("Destination")
		.and_then(|value| value.to_str().ok())
		.is_some_and(|raw| path::has_control_char(strip_to_path(raw)))
	{
		return StatusCode::BAD_REQUEST.into_response();
	}
	let Some(dest_path) = destination_path(root, headers) else {
		return StatusCode::FORBIDDEN.into_response();
	};
	if sync_handler::is_reserved(&dest_path) {
		return StatusCode::FORBIDDEN.into_response();
	}
	// A calendar object or contact is held to the same size however it got
	// its name, so a report can always return it on its own.
	if source_meta.is_file()
		&& source_meta.len() > MAX_RESOURCE_BYTES
		&& (caldav::is_ics_path(&uri_name(&dest_path))
			|| carddav::is_vcard_path(&uri_name(&dest_path)))
	{
		return StatusCode::PAYLOAD_TOO_LARGE.into_response();
	}
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
	// A `COPY` adds the source's real size, a collection included, and frees
	// what it replaces. A `MOVE` ends with no more bytes than it started with;
	// it takes the account's lock so it cannot interleave with a `COPY`.
	let mut reservation = if remove {
		quota.exclusive().await
	} else {
		match quota
			.admit(Change {
				copies: Some(source.to_path_buf()),
				replaces: dest_existed.then(|| dest_path.clone()),
				..Change::default()
			})
			.await
		{
			Ok(reservation) => reservation,
			Err(response) => return *response,
		}
	};
	// With the lock held, so the depth of the source cannot grow between this
	// check and the copy.
	if let Err(response) = quota.check_create(&dest_path, Some(source)).await {
		reservation.invalidate();
		return *response;
	}
	if let Err(response) = perform_copy(source, &dest_path, dest_was_dir).await {
		reservation.invalidate();
		bounds::forget_counts(&[&dest_path]);
		return *response;
	}
	if !source_meta.is_dir() {
		sync_handler::log_member(&dest_path, false).await;
	}
	if remove {
		let removal = if source_meta.is_dir() {
			tokio::fs::remove_dir_all(source).await
		} else {
			tokio::fs::remove_file(source).await
		};
		if removal.is_err() {
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		}
		bounds::forget_counts(&[source, &dest_path]);
		if !source_meta.is_dir() {
			sync_handler::log_member(source, true).await;
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
			// A copied calendar starts its own change log: tokens issued for
			// the source must not be valid on the copy.
			if child
				.file_name()
				.to_str()
				.is_some_and(super::super::sync::is_internal)
			{
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
