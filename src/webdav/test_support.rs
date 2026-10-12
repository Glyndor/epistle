//! Shared fixtures for the in-process WebDAV tests: a router over a temp
//! directory with two accounts, a request helper, and the MKCOL body that
//! creates an addressbook.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use crate::test_fixtures as fixtures;

/// Extended MKCOL body creating an addressbook collection.
pub const MKCOL_ADDRESSBOOK: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
	<D:set><D:prop><D:resourcetype>
		<D:collection/><C:addressbook/>
	</D:resourcetype></D:prop></D:set>
</D:mkcol>"#;

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

/// A WebDAV router over `dir` with the accounts `alice` and `bob`.
pub fn test_app(dir: &std::path::Path) -> Router {
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
	super::router(store.handle(), dir.to_path_buf())
}

/// Send one request as `alice` and return the status and the body as text.
pub async fn send_as_alice(
	app: &Router,
	method: &str,
	path: &str,
	headers: &[(&str, &str)],
	body: &[u8],
) -> (StatusCode, String) {
	let creds = format!("alice:{}", fixtures::password());
	let mut builder = Request::builder().method(method).uri(path).header(
		header::AUTHORIZATION,
		format!("Basic {}", base64_encode(creds.as_bytes())),
	);
	for (name, value) in headers {
		builder = builder.header(*name, *value);
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
	(status, String::from_utf8_lossy(&bytes).into_owned())
}
