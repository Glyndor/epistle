use super::{ReportKind, etag, hrefs, is_addressbook, report_kind};
use crate::webdav::router;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// Standard base64 encode for building Basic credentials (mirrors the handler
/// test helper).
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

/// Build a router backed by a temp data dir with `alice`/`pw-a` and `bob`/`pw-b`.
fn test_app(dir: &std::path::Path) -> Router {
	let account = |name: &str, pw: &str| crate::config::Account {
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some(crate::smtp::auth::hash_password(pw).expect("hash")),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
	};
	let store = crate::directory_store::AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![account("alice", "pw-a"), account("bob", "pw-b")],
	)
	.expect("store");
	router(store.handle(), dir.to_path_buf())
}

/// Send a request and return its status, body bytes and headers.
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

const ALICE: &str = "alice:pw-a";
const BOB: &str = "bob:pw-b";

const MKCOL_ADDRESSBOOK: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
	<D:set><D:prop><D:resourcetype>
		<D:collection/><C:addressbook/>
	</D:resourcetype></D:prop></D:set>
</D:mkcol>"#;

const VCARD: &[u8] = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nEND:VCARD\r\n";

#[tokio::test]
async fn report_kind_detects_both_reports() {
	assert_eq!(
		report_kind("<C:addressbook-multiget/>"),
		Some(ReportKind::Multiget)
	);
	assert_eq!(
		report_kind("<C:addressbook-query/>"),
		Some(ReportKind::Query)
	);
	assert_eq!(report_kind("<D:sync-collection/>"), None);
}

#[tokio::test]
async fn hrefs_extracts_values_in_order() {
	let body = "<C:addressbook-multiget xmlns:D=\"DAV:\">\
		<D:href>/alice/book/a.vcf</D:href>\
		<D:href> /alice/book/b.vcf </D:href>\
		</C:addressbook-multiget>";
	assert_eq!(hrefs(body), vec!["/alice/book/a.vcf", "/alice/book/b.vcf"]);
}

#[tokio::test]
async fn etag_changes_when_content_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("c.vcf");
	std::fs::write(&path, b"one").expect("write");
	let first = etag(&std::fs::metadata(&path).expect("meta"));
	std::thread::sleep(std::time::Duration::from_millis(10));
	std::fs::write(&path, b"two-longer").expect("write");
	let second = etag(&std::fs::metadata(&path).expect("meta"));
	assert!(first.starts_with('"') && first.ends_with('"'));
	assert_ne!(first, second);
}

#[tokio::test]
async fn marker_flags_addressbook() {
	let dir = tempfile::tempdir().expect("tempdir");
	let book = dir.path().join("book");
	std::fs::create_dir(&book).expect("mkdir");
	assert!(!is_addressbook(&book));
	assert!(super::mark_addressbook(&book).await);
	assert!(is_addressbook(&book));
}

#[tokio::test]
async fn addressbook_mkcol_then_propfind_resourcetype() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/book",
		Some(ALICE),
		&[("Depth", "0".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert!(text.contains("<C:addressbook/>"));
	assert!(text.contains("<D:collection/>"));
}

#[tokio::test]
async fn vcard_put_get_roundtrips_with_type_and_etag() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	let (status, _, put_headers) = send(&app, "PUT", "/book/a.vcf", Some(ALICE), &[], VCARD).await;
	assert_eq!(status, StatusCode::CREATED);
	assert!(put_headers.get(header::ETAG).is_some());
	let (status, body, get_headers) = send(&app, "GET", "/book/a.vcf", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, VCARD);
	assert_eq!(get_headers.get(header::CONTENT_TYPE).unwrap(), "text/vcard");
	assert!(get_headers.get(header::ETAG).is_some());
}

#[tokio::test]
async fn options_advertises_addressbook() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, resp_headers) = send(&app, "OPTIONS", "/", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	let dav = resp_headers.get("DAV").unwrap().to_str().unwrap();
	assert!(dav.contains("addressbook"));
	let allow = resp_headers.get(header::ALLOW).unwrap().to_str().unwrap();
	assert!(allow.contains("REPORT"));
}

#[tokio::test]
async fn multiget_returns_requested_cards() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	send(&app, "PUT", "/book/a.vcf", Some(ALICE), &[], VCARD).await;
	send(&app, "PUT", "/book/b.vcf", Some(ALICE), &[], VCARD).await;
	let report = "<C:addressbook-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\
		<D:href>/book/a.vcf</D:href></C:addressbook-multiget>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/book",
		Some(ALICE),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 1);
	assert!(text.contains("/book/a.vcf"));
	assert!(text.contains("Ada Lovelace"));
	assert!(text.contains("<D:getetag>"));
	assert!(text.contains("<C:address-data>"));
}

#[tokio::test]
async fn query_returns_all_cards() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	send(&app, "PUT", "/book/a.vcf", Some(ALICE), &[], VCARD).await;
	send(&app, "PUT", "/book/b.vcf", Some(ALICE), &[], VCARD).await;
	let report = "<C:addressbook-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\
		<D:prop><D:getetag/><C:address-data/></D:prop></C:addressbook-query>";
	let (status, body, _) = send(
		&app,
		"REPORT",
		"/book",
		Some(ALICE),
		&[("Depth", "1".to_string())],
		report.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<C:address-data>").count(), 2);
}

#[tokio::test]
async fn report_bad_body_is_bad_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	let (status, _, _) = send(
		&app,
		"REPORT",
		"/book",
		Some(ALICE),
		&[],
		b"<D:sync-collection xmlns:D=\"DAV:\"/>",
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn multiget_traversal_href_is_not_served() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	send(&app, "PUT", "/book/a.vcf", Some(ALICE), &[], VCARD).await;
	let report = "<C:addressbook-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\
		<D:href>/../../bob/dav/secret.vcf</D:href>\
		<D:href>/book/../../../bob/dav/secret.vcf</D:href></C:addressbook-multiget>";
	let (status, body, _) =
		send(&app, "REPORT", "/book", Some(ALICE), &[], report.as_bytes()).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	// The escaping hrefs resolve to nothing — no card lines in the response.
	assert_eq!(text.matches("<D:response>").count(), 0);
}

#[tokio::test]
async fn report_account_isolation_holds() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	// Bob stores a card.
	send(&app, "MKCOL", "/book", Some(BOB), &[], MKCOL_ADDRESSBOOK).await;
	send(&app, "PUT", "/book/secret.vcf", Some(BOB), &[], VCARD).await;
	// Alice asks for the same path: she gets her own (empty) tree, never Bob's.
	send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	let report = "<C:addressbook-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\
		<D:href>/book/secret.vcf</D:href></C:addressbook-multiget>";
	let (status, body, _) =
		send(&app, "REPORT", "/book", Some(ALICE), &[], report.as_bytes()).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	// Alice's tree has no such card; nothing is returned.
	assert_eq!(text.matches("<D:response>").count(), 0);
}

#[tokio::test]
async fn report_unauthenticated_is_challenged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(
		&app,
		"REPORT",
		"/book",
		None,
		&[],
		b"<C:addressbook-query xmlns:C=\"urn:ietf:params:xml:ns:carddav\"/>",
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn propfind_discovery_returns_home_set() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let body = "<D:propfind xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:carddav\">\
		<D:prop><D:current-user-principal/><C:addressbook-home-set/></D:prop></D:propfind>";
	let (status, out, _) = send(
		&app,
		"PROPFIND",
		"/alice/",
		Some(ALICE),
		&[("Depth", "0".to_string())],
		body.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("<C:addressbook-home-set>"));
	assert!(text.contains("<D:current-user-principal>"));
	assert!(text.contains("/alice/"));
}
