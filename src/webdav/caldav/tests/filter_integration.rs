//! End-to-end `calendar-query` filter tests (RFC 4791 §9.7).
//!
//! The unit tests in `src/webdav/caldav_filter/tests/base.rs` cover the filter
//! parser and matcher; the tests here drive the filter through the
//! WebDAV handler to make sure the integration holds.

use crate::test_fixtures as fixtures;
use crate::webdav::router;

const MKCOL_CALENDAR: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
	<D:set><D:prop><D:resourcetype>
		<D:collection/><C:calendar/>
	</D:resourcetype></D:prop></D:set>
</D:mkcol>"#;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn base64_encode(input: &[u8]) -> String {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::new();
	for chunk in input.chunks(3) {
		let b = [
			chunk[0],
			*chunk.get(1).unwrap_or(&0),
			*chunk.get(2).unwrap_or(&0),
		];
		let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
		out.push(ALPHABET[(n >> 18) as usize & 63] as char);
		out.push(ALPHABET[(n >> 12) as usize & 63] as char);
		out.push(if chunk.len() > 1 {
			ALPHABET[(n >> 6) as usize & 63] as char
		} else {
			'='
		});
		out.push(if chunk.len() > 2 {
			ALPHABET[n as usize & 63] as char
		} else {
			'='
		});
	}
	out
}

fn test_app(dir: &std::path::Path) -> Router {
	let account = |name: &str, pw: &str| crate::config::Account {
		display_name: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some(crate::smtp::auth::hash_password(pw).expect("hash")),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = crate::directory_store::AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![
			account("alice", fixtures::password()),
			account("bob", fixtures::second_password()),
		],
	)
	.expect("store");
	router(store.handle(), dir.to_path_buf())
}

async fn send(
	app: &Router,
	method: &str,
	path: &str,
	auth: Option<&str>,
	headers: &[(&str, String)],
	body: &[u8],
) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
	let mut builder = Request::builder().method(method).uri(path);
	if let Some(creds) = auth {
		let encoded = base64_encode(creds.as_bytes());
		builder = builder.header(
			axum::http::header::AUTHORIZATION,
			format!("Basic {encoded}"),
		);
	}
	for (name, value) in headers {
		builder = builder.header(*name, value);
	}
	let response = app
		.clone()
		.oneshot(builder.body(Body::from(body.to_vec())).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let resp_headers = response.headers().clone();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, bytes.to_vec(), resp_headers)
}

fn alice() -> String {
	format!("alice:{}", fixtures::password())
}

const EVENT: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTART:20260115T090000Z\r\nDTEND:20260115T100000Z\r\nSUMMARY:One\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const RECURRING: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:r1\r\nDTSTART:20260101T080000Z\r\nDTEND:20260101T090000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:Daily\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const TODO: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:t1\r\nSUMMARY:Buy milk\r\nDUE:20260115T100000Z\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";

/// A `calendar-query` whose `<C:time-range>` covers the event returns
/// the event; the same report with a window that misses the event
/// returns an empty list. The recurrence case asserts that a
/// recurring event with an occurrence inside the window is included.
#[tokio::test]
async fn calendar_query_time_range_includes_overlapping_event() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	// 2025-12-25T00:00:00Z to 2026-02-01T00:00:00Z covers the event
	// at 2026-01-15T09:00:00Z.
	let report = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/><C:calendar-data/></D:prop>\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:time-range start=\"20251225T000000Z\" end=\"20260201T000000Z\"/>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 1);
	assert!(text.contains("/cal/e1.ics"));
}

#[tokio::test]
async fn calendar_query_time_range_excludes_outside_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	// 2023-11-15T00:00:00Z to 2023-11-16T00:00:00Z is well before the
	// event.
	let report = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/><C:calendar-data/></D:prop>\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:time-range start=\"20231115T000000Z\" end=\"20231116T000000Z\"/>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 0);
}

#[tokio::test]
async fn calendar_query_includes_recurring_occurrence_in_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/r1.ics", Some(&alice()), &[], RECURRING).await;
	// The recurring event has occurrences 2026-01-01, -02, -03
	// 08:00-09:00Z. A window from 2026-01-02T00:00Z to
	// 2026-01-03T00:00Z overlaps the 2nd occurrence.
	let report = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/><C:calendar-data/></D:prop>\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:time-range start=\"20260102T000000Z\" end=\"20260103T000000Z\"/>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	// The recurring event is included; at least one of its
	// occurrences lands in the window.
	assert!(text.contains("/cal/r1.ics"));
}

#[tokio::test]
async fn calendar_query_vtodo_filter_excludes_events() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	send(&app, "PUT", "/cal/t1.ics", Some(&alice()), &[], TODO).await;
	let report = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/><C:calendar-data/></D:prop>\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VTODO\"/>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	// Only the VTODO is included, not the VEVENT.
	assert!(text.contains("/cal/t1.ics"));
	assert!(!text.contains("/cal/e1.ics"));
}

#[tokio::test]
async fn calendar_query_unsupported_filter_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	// `<C:limit-recurrence-set>` is a real CalDAV element we do not
	// implement; the server should answer 403 with
	// `CALDAV:supported-filter` rather than silently ignoring it.
	let report = "<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/></D:prop>\
		<C:filter>\
		<C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\">\
		<C:limit-recurrence-set/>\
		</C:comp-filter>\
		</C:comp-filter>\
		</C:filter>\
		</C:calendar-query>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("<C:supported-filter"));
}
