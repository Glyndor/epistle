use crate::test_support::fixtures;
use crate::webdav::router;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// Standard base64 encode for building Basic credentials.
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

/// Build a router backed by a temp data dir with two accounts: `alice`
/// and `bob`. Returns the router and the temp dir (kept alive).
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

/// Send a request and return its status and body bytes. `auth` is a
/// `login:password` pair encoded as Basic when `Some`.
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

#[tokio::test]
async fn put_then_get_roundtrips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "PUT", "/hello.txt", Some(&alice()), &[], b"world").await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, body, _) = send(&app, "GET", "/hello.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, b"world");
}

#[tokio::test]
async fn put_replace_returns_no_content() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/a.txt", Some(&alice()), &[], b"one").await;
	let (status, _, _) = send(&app, "PUT", "/a.txt", Some(&alice()), &[], b"two").await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (_, body, _) = send(&app, "GET", "/a.txt", Some(&alice()), &[], b"").await;
	assert_eq!(body, b"two");
}

#[tokio::test]
async fn put_into_missing_collection_is_conflict() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "PUT", "/nope/a.txt", Some(&alice()), &[], b"x").await;
	assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_missing_is_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "GET", "/ghost.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn head_returns_headers_no_body() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/h.txt", Some(&alice()), &[], b"12345").await;
	let (status, body, resp_headers) = send(&app, "HEAD", "/h.txt", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	assert!(body.is_empty());
	assert_eq!(resp_headers.get(header::CONTENT_LENGTH).unwrap(), "5");
}

#[tokio::test]
async fn options_advertises_dav_and_allow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, resp_headers) = send(&app, "OPTIONS", "/", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	let dav = resp_headers.get("DAV").unwrap().to_str().unwrap();
	assert!(dav.contains('1'));
	assert!(dav.contains("addressbook"));
	let allow = resp_headers.get(header::ALLOW).unwrap().to_str().unwrap();
	assert!(allow.contains("PROPFIND"));
	assert!(allow.contains("MKCOL"));
}

#[tokio::test]
async fn mkcol_creates_collection() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "MKCOL", "/docs", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::CREATED);
	// A PUT into the new collection now succeeds.
	let (status, _, _) = send(&app, "PUT", "/docs/a.txt", Some(&alice()), &[], b"x").await;
	assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn mkcol_existing_is_method_not_allowed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/docs", Some(&alice()), &[], b"").await;
	let (status, _, _) = send(&app, "MKCOL", "/docs", Some(&alice()), &[], b"").await;
	assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn propfind_depth_zero_describes_resource() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/f.txt", Some(&alice()), &[], b"abcd").await;
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/f.txt",
		Some(&alice()),
		&[("Depth", "0".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	assert_eq!(text.matches("<D:response>").count(), 1);
	assert!(text.contains("<D:resourcetype/>"));
	assert!(text.contains("<D:getcontentlength>4</D:getcontentlength>"));
}

#[tokio::test]
async fn propfind_depth_one_lists_children() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/d", Some(&alice()), &[], b"").await;
	send(&app, "PUT", "/d/a.txt", Some(&alice()), &[], b"a").await;
	send(&app, "PUT", "/d/b.txt", Some(&alice()), &[], b"bb").await;
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/d",
		Some(&alice()),
		&[("Depth", "1".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	let text = String::from_utf8(body).unwrap();
	// The collection itself plus its two children.
	assert_eq!(text.matches("<D:response>").count(), 3);
	assert!(text.contains("<D:collection/>"));
	assert!(text.contains("a.txt"));
	assert!(text.contains("b.txt"));
}

#[tokio::test]
async fn propfind_missing_is_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(
		&app,
		"PROPFIND",
		"/none",
		Some(&alice()),
		&[("Depth", "0".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}
