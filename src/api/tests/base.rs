//! The fixtures every API test shares: the runtime bearer token, the
//! `ApiState` a test drives and the request helpers.

use super::*;
use crate::test_support::fixtures;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::collections::BTreeMap;
use tower::ServiceExt;

use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;
use std::sync::LazyLock;

// Share the runtime bearer token with both sides of each request.
pub(in super::super) static TOKEN: LazyLock<String> =
	LazyLock::new(|| fixtures::api_token().to_string());

pub(in crate::api) fn sha256_hash(token: &str) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
	let hex = digest
		.as_ref()
		.iter()
		.fold(String::with_capacity(64), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
	format!("sha256:{hex}")
}

pub(in super::super) fn test_state(dir: &std::path::Path, queued: usize) -> ApiState {
	let spool = FsSpool::open(dir).expect("open spool");
	for i in 0..queued {
		spool
			.store(
				&AcceptedMessage {
					reverse_path: format!("a{i}@example.org"),
					recipients: vec![format!("r{i}@elsewhere.example")],
					data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
					require_tls: false,
					mailbox: None,
					tlsrpt_verified: false,
					sender_verified: false,
					no_dsn: Vec::new(),
				},
				None,
				&BTreeMap::new(),
			)
			.expect("store");
	}
	let accounts = vec![crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle())
}

pub(in super::super) async fn request(
	app: &Router,
	method: &str,
	path: &str,
	token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
	request_with_body(app, method, path, token, None).await
}

pub(in super::super) async fn request_with_body(
	app: &Router,
	method: &str,
	path: &str,
	token: Option<&str>,
	body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	let mut builder = Request::builder().method(method).uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let body = match body {
		Some(json) => {
			builder = builder.header(header::CONTENT_TYPE, "application/json");
			Body::from(json.to_string())
		}
		None => Body::empty(),
	};
	let response = app
		.clone()
		.oneshot(builder.body(body).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json = if bytes.is_empty() {
		serde_json::Value::Null
	} else {
		serde_json::from_slice(&bytes).expect("json body")
	};
	(status, json)
}

/// Like `request`, but returns the raw response body (for non-JSON endpoints).
pub(in super::super) async fn request_raw(
	app: &Router,
	path: &str,
	token: Option<&str>,
) -> (StatusCode, Vec<u8>) {
	let mut builder = Request::builder().method("GET").uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let response = app
		.clone()
		.oneshot(builder.body(Body::empty()).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, bytes.to_vec())
}
