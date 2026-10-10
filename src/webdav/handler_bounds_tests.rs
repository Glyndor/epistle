//! WebDAV request-bound regression tests — added by `fix/dav-jmap-bounds`.

use std::os::unix::fs::symlink;

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
		allowed_protocols: None,
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

/// Send a request and return its status and body bytes.
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

/// Place a symlink inside alice's DAV tree that points outside it. The link
/// target is a regular file under the temp data dir but outside
/// `accounts/alice/dav`.
fn install_symlink_escape(dir: &std::path::Path) -> std::path::PathBuf {
	let alice = dir.join("accounts").join("alice").join("dav");
	std::fs::create_dir_all(&alice).expect("alice dav");
	let outside = dir.join("outside.txt");
	std::fs::write(&outside, b"OUTSIDE_SECRET").expect("outside");
	symlink(&outside, alice.join("escape.txt")).expect("symlink");
	outside
}

#[tokio::test]
async fn get_through_symlink_does_not_leak_outside_bytes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = install_symlink_escape(dir.path());
	let app = test_app(dir.path());
	let (status, body) = send(&app, "GET", "/escape.txt", Some(ALICE), &[], b"").await;
	// The symlink escapes the root; the request must be refused and the outside
	// file's bytes must never appear in the response.
	assert!(
		status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
		"expected 403 or 404, got {status}"
	);
	assert_ne!(body, b"OUTSIDE_SECRET", "outside bytes leaked");
	// Outside file is still on disk.
	assert!(outside.exists());
}

#[tokio::test]
async fn put_through_symlink_does_not_modify_outside_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = install_symlink_escape(dir.path());
	let app = test_app(dir.path());
	let (status, _) = send(
		&app,
		"PUT",
		"/escape.txt",
		Some(ALICE),
		&[],
		b"INJECTED",
	)
	.await;
	assert!(
		status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
		"expected 403 or 404, got {status}"
	);
	let bytes = std::fs::read(&outside).expect("outside readable");
	assert_eq!(bytes, b"OUTSIDE_SECRET", "outside file was modified via symlink");
}

