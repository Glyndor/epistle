//! Linear-scan regression tests for the REPORT body scan in CardDAV and CalDAV.

use std::sync::atomic::Ordering;

use super::*;
use crate::webdav::router;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// Standard base64 encode for building Basic credentials.
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

/// Build a router backed by a temp data dir with `alice`/`pw-a`.
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
		vec![account("alice", "pw-a")],
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
) -> (StatusCode, Vec<u8>) {
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
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, bytes.to_vec())
}

const ALICE: &str = "alice:pw-a";

const MKCOL_ADDRESSBOOK: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
	<D:set><D:prop><D:resourcetype>
		<D:collection/><C:addressbook/>
	</D:resourcetype></D:prop></D:set>
</D:mkcol>"#;

const VCARD: &[u8] = b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nEND:VCARD\r\n";

/// The previous REPORT body scan restarted from the cursor after every
/// non-match, and `tag.split(['>', ' ', '/']).next()` walks the entire
/// remaining body when the tag is unclosed (the split returns the
/// whole tail as one piece). With N unclosed tags, the splits together
/// visit N(N+1)/2 bytes, so the scan is O(N²) in body bytes. The linear
/// scan walks each byte once and advances past the tag name in one
/// jump, so the total stays under a small linear multiple of the
/// body length.
#[test]
fn find_open_scans_a_20000_tag_body_in_linear_steps() {
	// 20 000 unclosed `<a` tags, 2 bytes each. Body length: 40 000.
	// Quadratic: each `<`'s tag-name split iterates the rest of the
	// body, totalling ~200 M bytes compared. Linear: each byte is
	// visited a small constant number of times, totalling well under
	// 10 × 40 000 = 400 000 bytes compared.
	let mut body = String::with_capacity(20_000 * 2);
	for _ in 0..20_000 {
		body.push_str("<a");
	}
	let body_len = body.len();
	SCAN_STEPS.store(0, Ordering::Relaxed);
	let _ = find_open(&body, "href");
	let steps = SCAN_STEPS.load(Ordering::Relaxed);
	assert!(
		steps <= 10 * body_len as u64,
		"scan did {steps} steps on a {body_len}-byte body (linear bound {})",
		10 * body_len
	);
}

/// The first matching `<...:href>` is still found at the same byte index
/// after the linear refactor.
#[test]
fn find_open_returns_first_match_position() {
	let body = "<C:addressbook-multiget xmlns:D=\"DAV:\">\
		<D:href>/a.vcf</D:href>\
		<D:href>/b.vcf</D:href>\
		</C:addressbook-multiget>";
	let pos = find_open(body, "href").expect("href present");
	// The first `<D:href>` opens at byte 39 in the body above.
	assert_eq!(pos, 39);
	assert!(find_open(body, "no-such-tag").is_none());
}

/// `hrefs` still extracts every `<...:href>VALUE</...:href>` in document
/// order with whitespace trimmed.
#[test]
fn hrefs_still_extracts_values_after_linear_refactor() {
	let body = "<C:addressbook-multiget xmlns:D=\"DAV:\">\
		<D:href>/a.vcf</D:href>\
		<D:href> /b.vcf </D:href>\
		</C:addressbook-multiget>";
	assert_eq!(hrefs(body), vec!["/a.vcf", "/b.vcf"]);
}

/// Functional regression: a real REPORT on a real addressbook returns the
/// same shape it did before the linear refactor.
#[tokio::test]
async fn multiget_still_returns_requested_cards() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/book", Some(ALICE), &[], MKCOL_ADDRESSBOOK).await;
	send(&app, "PUT", "/book/a.vcf", Some(ALICE), &[], VCARD).await;
	send(&app, "PUT", "/book/b.vcf", Some(ALICE), &[], VCARD).await;
	let body = "<C:addressbook-multiget xmlns:D=\"DAV:\">\
		<D:href>/book/a.vcf</D:href>\
		<D:href>/book/b.vcf</D:href>\
		</C:addressbook-multiget>";
	let (status, out) = send(
		&app,
		"REPORT",
		"/book",
		Some(ALICE),
		&[("Depth", "1".to_string())],
		body.as_bytes(),
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(out).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 2);
	assert!(text.contains("Ada Lovelace"));
}
