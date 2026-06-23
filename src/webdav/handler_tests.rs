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

/// Build a router backed by a temp data dir with two accounts: `alice`/`pw-a`
/// and `bob`/`pw-b`. Returns the router and the temp dir (kept alive).
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

/// Send a request and return its status and body bytes. `auth` is a
/// `login:password` pair encoded as Basic when `Some`.
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

#[tokio::test]
async fn put_then_get_roundtrips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "PUT", "/hello.txt", Some(ALICE), &[], b"world").await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, body, _) = send(&app, "GET", "/hello.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, b"world");
}

#[tokio::test]
async fn put_replace_returns_no_content() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/a.txt", Some(ALICE), &[], b"one").await;
	let (status, _, _) = send(&app, "PUT", "/a.txt", Some(ALICE), &[], b"two").await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (_, body, _) = send(&app, "GET", "/a.txt", Some(ALICE), &[], b"").await;
	assert_eq!(body, b"two");
}

#[tokio::test]
async fn put_into_missing_collection_is_conflict() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "PUT", "/nope/a.txt", Some(ALICE), &[], b"x").await;
	assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_missing_is_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "GET", "/ghost.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn head_returns_headers_no_body() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/h.txt", Some(ALICE), &[], b"12345").await;
	let (status, body, resp_headers) = send(&app, "HEAD", "/h.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	assert!(body.is_empty());
	assert_eq!(resp_headers.get(header::CONTENT_LENGTH).unwrap(), "5");
}

#[tokio::test]
async fn options_advertises_dav_and_allow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, resp_headers) = send(&app, "OPTIONS", "/", Some(ALICE), &[], b"").await;
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
	let (status, _, _) = send(&app, "MKCOL", "/docs", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::CREATED);
	// A PUT into the new collection now succeeds.
	let (status, _, _) = send(&app, "PUT", "/docs/a.txt", Some(ALICE), &[], b"x").await;
	assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn mkcol_existing_is_method_not_allowed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/docs", Some(ALICE), &[], b"").await;
	let (status, _, _) = send(&app, "MKCOL", "/docs", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn propfind_depth_zero_describes_resource() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/f.txt", Some(ALICE), &[], b"abcd").await;
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/f.txt",
		Some(ALICE),
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
	send(&app, "MKCOL", "/d", Some(ALICE), &[], b"").await;
	send(&app, "PUT", "/d/a.txt", Some(ALICE), &[], b"a").await;
	send(&app, "PUT", "/d/b.txt", Some(ALICE), &[], b"bb").await;
	let (status, body, _) = send(
		&app,
		"PROPFIND",
		"/d",
		Some(ALICE),
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
		Some(ALICE),
		&[("Depth", "0".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_removes_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/x.txt", Some(ALICE), &[], b"x").await;
	let (status, _, _) = send(&app, "DELETE", "/x.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (status, _, _) = send(&app, "GET", "/x.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_collection_recursively() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "MKCOL", "/d", Some(ALICE), &[], b"").await;
	send(&app, "PUT", "/d/a.txt", Some(ALICE), &[], b"a").await;
	let (status, _, _) = send(&app, "DELETE", "/d", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (status, _, _) = send(&app, "GET", "/d/a.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_missing_is_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "DELETE", "/none", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn copy_duplicates_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/src.txt", Some(ALICE), &[], b"data").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/src.txt",
		Some(ALICE),
		&[("Destination", "/dst.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (_, src, _) = send(&app, "GET", "/src.txt", Some(ALICE), &[], b"").await;
	let (_, dst, _) = send(&app, "GET", "/dst.txt", Some(ALICE), &[], b"").await;
	assert_eq!(src, b"data");
	assert_eq!(dst, b"data");
}

#[tokio::test]
async fn move_relocates_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/src.txt", Some(ALICE), &[], b"data").await;
	let (status, _, _) = send(
		&app,
		"MOVE",
		"/src.txt",
		Some(ALICE),
		&[("Destination", "/moved.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, _, _) = send(&app, "GET", "/src.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (_, dst, _) = send(&app, "GET", "/moved.txt", Some(ALICE), &[], b"").await;
	assert_eq!(dst, b"data");
}

#[tokio::test]
async fn copy_no_overwrite_is_precondition_failed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/a.txt", Some(ALICE), &[], b"a").await;
	send(&app, "PUT", "/b.txt", Some(ALICE), &[], b"b").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/a.txt",
		Some(ALICE),
		&[
			("Destination", "/b.txt".to_string()),
			("Overwrite", "F".to_string()),
		],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn copy_with_absolute_url_destination() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/s.txt", Some(ALICE), &[], b"u").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/s.txt",
		Some(ALICE),
		&[("Destination", "https://dav.example.org/d.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, _, _) = send(&app, "GET", "/d.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn traversal_in_path_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "PUT", "/%2e%2e/escape.txt", Some(ALICE), &[], b"x").await;
	assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn traversal_in_destination_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send(&app, "PUT", "/s.txt", Some(ALICE), &[], b"x").await;
	let (status, _, _) = send(
		&app,
		"COPY",
		"/s.txt",
		Some(ALICE),
		&[("Destination", "/../../bob/dav/stolen.txt".to_string())],
		b"",
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_is_challenged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, resp_headers) = send(&app, "GET", "/x.txt", None, &[], b"").await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert!(
		resp_headers
			.get(header::WWW_AUTHENTICATE)
			.unwrap()
			.to_str()
			.unwrap()
			.starts_with("Basic ")
	);
}

#[tokio::test]
async fn wrong_password_is_challenged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "GET", "/x.txt", Some("alice:wrong"), &[], b"").await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn account_isolation_is_enforced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	// Alice writes a private file.
	send(&app, "PUT", "/secret.txt", Some(ALICE), &[], b"alice-only").await;
	// Bob requests the same path: he gets his own (empty) tree, never Alice's.
	let (status, _, _) = send(&app, "GET", "/secret.txt", Some(BOB), &[], b"").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	// Bob writes his own file; Alice's is untouched and distinct.
	send(&app, "PUT", "/secret.txt", Some(BOB), &[], b"bob-only").await;
	let (_, alice_body, _) = send(&app, "GET", "/secret.txt", Some(ALICE), &[], b"").await;
	let (_, bob_body, _) = send(&app, "GET", "/secret.txt", Some(BOB), &[], b"").await;
	assert_eq!(alice_body, b"alice-only");
	assert_eq!(bob_body, b"bob-only");
}

#[tokio::test]
async fn unknown_method_is_method_not_allowed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	let (status, _, _) = send(&app, "LOCK", "/x.txt", Some(ALICE), &[], b"").await;
	assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}
