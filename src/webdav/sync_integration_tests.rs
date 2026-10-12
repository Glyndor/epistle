//! End-to-end `sync-collection` tests (RFC 6578) covering both the
//! CalDAV (calendar) and CardDAV (addressbook) paths. The unit tests in
//! `sync_tests.rs` cover the change-log bookkeeping; the tests here
//! cover the whole REPORT round trip through the WebDAV handler.

use crate::test_fixtures as fixtures;
use crate::webdav::router;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
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

fn alice() -> String {
	format!("alice:{}", fixtures::password())
}

const MKCOL_CALENDAR: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
	<D:set><D:prop><D:resourcetype>
		<D:collection/><C:calendar/>
	</D:resourcetype></D:prop></D:set>
</D:mkcol>"#;

const MKCOL_ADDRESSBOOK: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
	<D:set><D:prop><D:resourcetype>
		<D:collection/><C:addressbook/>
	</D:resourcetype></D:prop></D:set>
</D:mkcol>"#;

const EVENT: &[u8] =
	b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:e1\r\nDTSTART:20260115T090000Z\r\nDTEND:20260115T100000Z\r\nSUMMARY:One\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const VCARD: &[u8] = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nEND:VCARD\r\n";

const SYNC_REPORT: &[u8] =
	b"<D:sync-collection xmlns:D=\"DAV:\"><D:sync-token/></D:sync-collection>";

const SYNC_REPORT_LEVEL: &[u8] =
	b"<D:sync-collection xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:sync-level>1</D:sync-level><D:sync-token/></D:sync-collection>";

#[tokio::test]
async fn sync_collection_empty_token_lists_all_calendars() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/a.ics", Some(&alice()), &[], EVENT).await;
	send(&app, "PUT", "/cal/b.ics", Some(&alice()), &[], EVENT).await;
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	// The collection's own response carries the token and `getctag`.
	assert!(text.contains("<D:sync-token>urn:epistle:sync:"));
	assert!(text.contains("<CS:getctag>urn:epistle:sync:"));
	// Two events, each with its href, getetag, and calendar-data.
	assert!(text.contains("href>/cal/a.ics<"));
	assert!(text.contains("href>/cal/b.ics<"));
	assert!(text.contains("<CAL:calendar-data>"));
}

#[tokio::test]
async fn sync_collection_returns_404_for_deleted_resource() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/a.ics", Some(&alice()), &[], EVENT).await;
	// First sync: get the token, then delete, then sync again.
	let (_, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	let text = String::from_utf8(body).unwrap();
	let token = extract_token(&text).expect("token");
	// DELETE the event.
	send(&app, "DELETE", "/cal/a.ics", Some(&alice()), &[], b"").await;
	// Now sync again with the saved token: only the deletion comes back.
	let report = format!(
		"<D:sync-collection xmlns:D=\"DAV:\">\
		<D:sync-token>{token}</D:sync-token></D:sync-collection>"
	);
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
	assert!(text.contains("href>/cal/a.ics<"));
	assert!(text.contains("HTTP/1.1 404 Not Found"));
	// The current token is the new one, not the request token.
	let new_token = extract_token(&text).expect("new token");
	assert_ne!(new_token, token);
}

#[tokio::test]
async fn sync_collection_returns_change_after_put() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let (_, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	let token = extract_token(&String::from_utf8(body).unwrap()).expect("token");
	// Add a new event.
	send(&app, "PUT", "/cal/c.ics", Some(&alice()), &[], EVENT).await;
	// Sync with the previous token: exactly the new event.
	let report = format!(
		"<D:sync-collection xmlns:D=\"DAV:\">\
		<D:sync-token>{token}</D:sync-token></D:sync-collection>"
	);
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
	// One resource response, plus the collection response, plus the change.
	// We assert on the href specifically, and the 200 status (not 404).
	assert!(text.contains("href>/cal/c.ics<"));
	assert!(text.contains("HTTP/1.1 200 OK"));
	// And the new token is greater than the old one.
	let new_token = extract_token(&text).expect("new token");
	let new_n: u64 = new_token
		.strip_prefix("urn:epistle:sync:")
		.unwrap()
		.parse()
		.unwrap();
	let old_n: u64 = token
		.strip_prefix("urn:epistle:sync:")
		.unwrap()
		.parse()
		.unwrap();
	assert!(new_n > old_n, "new {new_n} should exceed old {old_n}");
}

#[tokio::test]
async fn sync_collection_garbage_token_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let report = "<D:sync-collection xmlns:D=\"DAV:\">\
		<D:sync-token>not-a-valid-token</D:sync-token></D:sync-collection>";
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
	assert!(text.contains("<D:valid-sync-token/>"));
}

#[tokio::test]
async fn sync_collection_expired_token_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	// Push past the retention cap by recording directly through the
	// change-log API: the HTTP loop in this test would be slow and the
	// disc content is irrelevant. A direct test of the retention is in
	// `sync_tests.rs`; here we just want the REPORT to be `403` for a
	// token the server no longer keeps.
	let coll = dir.path().join("accounts/alice/dav/cal");
	for i in 0..(super::MAX_ENTRIES + 50) {
		super::record(&coll, &format!("{i:04}.ics"), false).await;
	}
	let report = "<D:sync-collection xmlns:D=\"DAV:\">\
		<D:sync-token>urn:epistle:sync:1</D:sync-token></D:sync-collection>";
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
	assert!(text.contains("<D:valid-sync-token/>"));
}

#[tokio::test]
async fn sync_collection_infinite_level_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let report = "<D:sync-collection xmlns:D=\"DAV:\">\
		<D:sync-level>infinity</D:sync-level>\
		<D:sync-token/></D:sync-collection>";
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
	assert!(text.contains("<D:valid-sync-token/>"));
}

#[tokio::test]
async fn sync_collection_works_for_addressbook() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(&alice()), &[], MKCOL_ADDRESSBOOK).await;
	send(&app, "PUT", "/book/a.vcf", Some(&alice()), &[], VCARD).await;
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/book",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("<C:address-data>"));
	assert!(text.contains("Ada Lovelace"));
}

#[tokio::test]
async fn sync_collection_outside_calendar_or_addressbook_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	// A regular collection (no marker) refuses sync.
	let (status, _, _) = send(&app, "MKCOL", "/notbook", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/notbook",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("<D:valid-sync-token/>"));
}

#[tokio::test]
async fn getctag_changes_on_every_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	// Empty calendar: ctag is the empty-sequence token.
	let (_, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	let text = String::from_utf8(body).unwrap();
	let first = extract_token(&text).expect("first token");
	// PUT a new event: ctag changes.
	send(&app, "PUT", "/cal/a.ics", Some(&alice()), &[], EVENT).await;
	let (_, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	let text = String::from_utf8(body).unwrap();
	let second = extract_token(&text).expect("second token");
	assert_ne!(first, second);
	// PUT again: ctag moves again.
	send(&app, "PUT", "/cal/b.ics", Some(&alice()), &[], EVENT).await;
	let (_, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	let text = String::from_utf8(body).unwrap();
	let third = extract_token(&text).expect("third token");
	assert_ne!(second, third);
}

#[tokio::test]
async fn sync_collection_delete_then_create_appears_in_one_sync() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	send(&app, "PUT", "/cal/a.ics", Some(&alice()), &[], EVENT).await;
	let (_, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT,
	)
	.await;
	let token = extract_token(&String::from_utf8(body).unwrap()).expect("token");
	send(&app, "DELETE", "/cal/a.ics", Some(&alice()), &[], b"").await;
	send(&app, "PUT", "/cal/b.ics", Some(&alice()), &[], EVENT).await;
	let report = format!(
		"<D:sync-collection xmlns:D=\"DAV:\">\
		<D:sync-token>{token}</D:sync-token></D:sync-collection>"
	);
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
	assert!(text.contains("href>/cal/a.ics<"));
	assert!(text.contains("HTTP/1.1 404 Not Found"));
	assert!(text.contains("href>/cal/b.ics<"));
	assert!(text.contains("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn sync_collection_token_in_response_is_a_full_uri() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
	let (_, body, _) = send(
		&app,
		"REPORT",
		"/cal",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		SYNC_REPORT_LEVEL,
	)
	.await;
	let text = String::from_utf8(body).unwrap();
	// Both the property on the collection response and the ctag carry
	// the same token.
	let tokens: Vec<&str> = text
		.split("<D:sync-token>")
		.skip(1)
		.filter_map(|rest| rest.split("</D:sync-token>").next())
		.collect();
	assert!(!tokens.is_empty(), "no <D:sync-token> in body: {text}");
	for token in &tokens {
		assert!(token.starts_with("urn:epistle:sync:"));
	}
}

/// Pull the first `urn:epistle:sync:<n>` token out of a multistatus body.
fn extract_token(body: &str) -> Option<String> {
	let prefix = "urn:epistle:sync:";
	let start = body.find(prefix)?;
	let tail = &body[start + prefix.len()..];
	let end = tail
		.find(|c: char| !c.is_ascii_digit())
		.unwrap_or(tail.len());
	Some(format!("{prefix}{}", &tail[..end]))
}

#[tokio::test]
async fn propfind_advertises_sync_token_getctag_and_supported_report_set() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/cal", Some(&alice()), &[], MKCOL_CALENDAR).await;
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
	// Sync-token is a `urn:epistle:sync:<n>` URI.
	assert!(text.contains("<D:sync-token>urn:epistle:sync:"));
	// getctag is in the calendarserver namespace and carries the same value.
	assert!(text.contains(
		"<CS:getctag xmlns:CS=\"http://calendarserver.org/ns/\">urn:epistle:sync:"
	));
	// supported-report-set lists sync-collection.
	assert!(text.contains("<D:supported-report-set>"));
	assert!(text.contains("<D:report><D:sync-collection/></D:report>"));
}

#[tokio::test]
async fn propfind_on_addressbook_advertises_same_set() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(&alice()), &[], MKCOL_ADDRESSBOOK).await;
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/book",
		Some(&alice()),
		&[("Depth", "0".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("<D:sync-token>urn:epistle:sync:"));
	assert!(text.contains(
		"<CS:getctag xmlns:CS=\"http://calendarserver.org/ns/\">urn:epistle:sync:"
	));
	assert!(text.contains("<D:supported-report-set>"));
	assert!(text.contains("<D:report><D:sync-collection/></D:report>"));
}

#[tokio::test]
async fn propfind_on_plain_collection_does_not_advertise_sync() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/plain", Some(&alice()), &[], b"").await;
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/plain",
		Some(&alice()),
		&[("Depth", "0".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	// A regular collection has no sync-token, no getctag, and no
	// supported-report-set.
	assert!(!text.contains("<D:sync-token>"));
	assert!(!text.contains("getctag"));
	assert!(!text.contains("supported-report-set"));
}
