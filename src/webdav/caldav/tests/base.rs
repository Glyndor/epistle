use super::{ReportKind, is_calendar, report_kind, unfold};
use crate::test_support::fixtures;
use crate::webdav::router;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// Standard base64 encode for building Basic credentials (mirrors the carddav
/// test helper).
pub(super) fn base64_encode(input: &[u8]) -> String {
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

/// Build a router backed by a temp data dir with `alice` and `bob`.
pub(super) fn test_app(dir: &std::path::Path) -> Router {
	let account = |name: &str, pw: &str| crate::config::Account {
		send: None,
		receive: None,
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

/// Send a request and return its status, body bytes and headers.
pub(super) async fn send(
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
		builder = builder.header(header::AUTHORIZATION, format!("Basic {encoded}"));
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

pub(super) fn alice() -> String {
	format!("alice:{}", fixtures::password())
}
pub(super) fn bob() -> String {
	format!("bob:{}", fixtures::second_password())
}

pub(super) const MKCOL_CALENDAR: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
	<D:set><D:prop><D:resourcetype>
		<D:collection/><C:calendar/>
	</D:resourcetype></D:prop></D:set>
</D:mkcol>"#;

/// A single-occurrence event on 2026-01-15 from 09:00 to 10:00 UTC.
pub(super) const EVENT: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTART:20260115T090000Z\r\nDTEND:20260115T100000Z\r\nSUMMARY:One\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// A daily recurring event starting 2026-01-01 08:00, 1h long, 3 occurrences.
pub(super) const RECURRING: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:r1\r\nDTSTART:20260101T080000Z\r\nDTEND:20260101T090000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:Daily\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

#[tokio::test]
async fn report_kind_detects_three_reports() {
	assert_eq!(
		report_kind("<C:calendar-multiget/>"),
		Some(ReportKind::Multiget)
	);
	assert_eq!(report_kind("<C:calendar-query/>"), Some(ReportKind::Query));
	assert_eq!(
		report_kind("<C:free-busy-query/>"),
		Some(ReportKind::FreeBusy)
	);
	assert_eq!(report_kind("<C:addressbook-query/>"), None);
}

#[tokio::test]
async fn unfold_joins_continuation_lines() {
	let folded = "DESCRIPTION:Hello\r\n World\r\nSUMMARY:Hi";
	assert_eq!(unfold(folded), "DESCRIPTION:HelloWorld\nSUMMARY:Hi");
	// A tab continuation is unfolded the same way.
	assert_eq!(unfold("A:1\r\n\t2"), "A:12");
}

#[tokio::test]
async fn marker_flags_calendar() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cal = dir.path().join("cal");
	std::fs::create_dir(&cal).expect("mkdir");
	assert!(!is_calendar(&cal));
	assert!(super::mark_calendar(&cal).await);
	assert!(is_calendar(&cal));
}

#[tokio::test]
async fn calendar_mkcol_then_propfind_resourcetype() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/cal",
		Some(&alice()),
		&[("Depth", "0".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("<CAL:calendar/>"));
	assert!(text.contains("<D:collection/>"));
}

#[tokio::test]
async fn ics_put_get_roundtrips_with_type_and_etag() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let (status, _, put_headers) =
		send(&app, "PUT", "/cal/e1.ics", Some(&alice()), &[], EVENT).await;
	assert_eq!(status, StatusCode::CREATED);
	assert!(put_headers.get(header::ETAG).is_some());
	let (status, body, get_headers) =
		send(&app, "GET", "/cal/e1.ics", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	// VALARM is stored and returned verbatim.
	assert_eq!(body, EVENT);
	assert_eq!(
		get_headers.get(header::CONTENT_TYPE).unwrap(),
		"text/calendar"
	);
	assert!(get_headers.get(header::ETAG).is_some());
}

#[tokio::test]
async fn options_advertises_calendar_access() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, resp_headers) = send(&app, "OPTIONS", "/", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	let dav = resp_headers.get("DAV").unwrap().to_str().unwrap();
	assert!(dav.contains("calendar-access"));
	let allow = resp_headers.get(header::ALLOW).unwrap().to_str().unwrap();
	assert!(allow.contains("REPORT"));
	assert!(allow.contains("POST"));
}
