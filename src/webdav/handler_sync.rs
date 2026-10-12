//! The handler side of incremental sync: dispatching a `sync-collection`
//! REPORT, and logging every member write into the parent collection's
//! change log ([`super::super::sync`]).

use std::path::Path;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use super::super::{caldav, carddav, href, sync, sync_report};

/// Answer a `sync-collection` REPORT on `target`. Only calendars and
/// addressbooks keep a change log; any other resource answers `403` with
/// `DAV:supported-report`. RFC 6578 §3.2 defines the report for `Depth: 0`
/// only, so any other depth is `400`.
pub(super) async fn report(
	root: &Path,
	target: &Path,
	headers: &HeaderMap,
	body: &str,
) -> Response {
	if headers
		.get("Depth")
		.is_some_and(|depth| depth.as_bytes() != b"0")
	{
		return StatusCode::BAD_REQUEST.into_response();
	}
	let calendar = caldav::is_calendar(target);
	if !calendar && !carddav::is_addressbook(target) {
		return sync_report::precondition_failed("supported-report");
	}
	sync_report::report(root, target, calendar, body).await
}

/// Whether `target` names one of the change log's own files. They are not
/// resources: every method answers as if they did not exist, and nothing
/// can be copied or moved onto them.
pub(super) fn is_reserved(target: &Path) -> bool {
	target
		.file_name()
		.and_then(|name| name.to_str())
		.is_some_and(sync::is_internal)
}

/// Log that the file `member` was written (`removed == false`) or removed in
/// its parent directory, when that parent is a calendar or an addressbook.
/// Only direct member files are logged: a calendar or addressbook holds no
/// sub-collections a sync client could see.
pub(super) async fn log_member(member: &Path, removed: bool) {
	let Some(parent) = member.parent() else {
		return;
	};
	let Some(name) = member.file_name().and_then(|name| name.to_str()) else {
		return;
	};
	if caldav::is_calendar(parent) || carddav::is_addressbook(parent) {
		sync::record(parent, &[(href::segment(name), removed)]).await;
	}
}
