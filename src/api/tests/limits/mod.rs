//! The configured caps as the REST API, JMAP and SCIM answer them: addresses
//! at account creation, and message size on send and upload.

use super::base::{TOKEN, request_with_body};
use super::*;
use crate::limits::test_support::shared;
use crate::storage::FsSpool;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// alice and bob are static accounts of example.org; `extra` is the limits.
fn state(dir: &std::path::Path, extra: &str) -> ApiState {
	let account = |name: &str| crate::config::Account {
		send: None,
		receive: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
		display_name: None,
	};
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string(), "example.net".to_string()],
			std::collections::HashMap::new(),
			vec![account("alice"), account("bob")],
		)
		.expect("open store")
		.with_limits(shared(extra)),
	);
	ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string(), "example.net".to_string()],
		store.clone(),
		FsSpool::open(dir).expect("spool"),
	)
	.with_directory(store.handle())
}

const CAPS: &str = "[[limit_scope]]\naccount = \"alice\"\nmax_message_size = 70000\n\
	[[limit_scope]]\ndomain = \"example.net\"\nmax_addresses_per_account = 2\n";

async fn create(
	app: &axum::Router,
	name: &str,
	addresses: &[&str],
) -> (StatusCode, serde_json::Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": name, "addresses": addresses, "password": "correct horse battery staple 42"
		})),
	)
	.await
}

#[tokio::test]
async fn creating_an_account_over_the_address_cap_is_a_409_that_says_why() {
	let dir = tempfile::tempdir().unwrap();
	let app = router(state(dir.path(), CAPS));
	let (status, body) = create(
		&app,
		"carol",
		&["a@example.net", "b@example.net", "c@example.net"],
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	assert_eq!(body["error"]["code"], "limit_reached", "{body}");
	let message = body["error"]["message"].as_str().unwrap_or_default();
	for part in [
		"account carol",
		"2 addresses per account",
		"domain example.net",
		"remove an address",
	] {
		assert!(message.contains(part), "{message:?} lacks {part:?}");
	}
	let (status, body) = create(&app, "carol", &["a@example.net", "b@example.net"]).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, body) = create(
		&app,
		"dave",
		&["a@example.org", "b@example.org", "c@example.org"],
	)
	.await;
	assert_eq!(status, StatusCode::OK, "no cap on example.org: {body}");
}

async fn send_of(app: &axum::Router, from: &str, bytes: usize) -> (StatusCode, serde_json::Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"from": from, "to": ["someone@elsewhere.example"],
			"subject": "hi", "text": "x".repeat(bytes)
		})),
	)
	.await
}

#[tokio::test]
async fn a_send_over_the_cap_of_the_account_is_a_413_and_nothing_is_queued() {
	let dir = tempfile::tempdir().unwrap();
	let app = router(state(dir.path(), CAPS));
	let (status, body) = send_of(&app, "alice@example.org", 75_000).await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
	assert_eq!(body["error"]["code"], "message_too_large", "{body}");
	let message = body["error"]["message"].as_str().unwrap_or_default();
	assert!(
		message.contains("70000 bytes") && message.contains("account alice"),
		"{message}"
	);
	assert!(
		FsSpool::open(dir.path())
			.unwrap()
			.list()
			.unwrap()
			.is_empty()
	);
	let (status, body) = send_of(&app, "alice@example.org", 1_000).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, body) = send_of(&app, "bob@example.org", 75_000).await;
	assert_eq!(status, StatusCode::OK, "bob has no cap: {body}");
}

async fn upload(
	app: &axum::Router,
	account: &str,
	bytes: usize,
) -> (StatusCode, serde_json::Value) {
	let request = Request::builder()
		.method("POST")
		.uri(format!("/jmap/upload/{account}"))
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.header(header::CONTENT_TYPE, "application/octet-stream")
		.body(Body::from(vec![0u8; bytes]))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
	)
}

#[tokio::test]
async fn an_upload_over_the_cap_of_the_account_gets_the_limit_problem() {
	let dir = tempfile::tempdir().unwrap();
	let app = router(state(dir.path(), CAPS));
	let (status, body) = upload(&app, "alice", 70_001).await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
	assert_eq!(body["type"], "urn:ietf:params:jmap:error:limit", "{body}");
	assert_eq!(body["limit"], "maxSizeUpload", "{body}");
	assert!(
		body["detail"]
			.as_str()
			.unwrap_or_default()
			.contains("account alice"),
		"{body}"
	);
	let (status, body) = upload(&app, "alice", 70_000).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, _) = upload(&app, "bob", 200_000).await;
	assert_eq!(status, StatusCode::OK);
}
