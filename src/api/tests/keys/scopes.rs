//! The scope an API key carries, and what each scope admits.

use super::base::{TOKEN, request, request_with_body, test_state};
use super::*;
use crate::test_fixtures as fixtures;
use axum::http::StatusCode;

// --- Scope enforcement on the bearer middleware ---------------------------------

/// A read-only API key authenticates against `GET /api/v1/status` (the coarse
/// middleware scope is `Read`): this is the acceptance half of the read-vs-
/// write control.
#[tokio::test]
async fn read_scoped_key_is_admitted_on_get() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "reader".to_string(),
			hash: crate::api::api_keys::sha256_hash("reader-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request(&app, "GET", "/api/v1/status", Some("reader-secret")).await;
	assert_eq!(status, StatusCode::OK, "read scope admits a GET");
}

/// A read-only API key is rejected on `POST /api/v1/send` (the coarse
/// middleware scope is `Send`): this is the rejection half of the send
/// blast-radius control. Without this guard a leaked `read` key would be
/// indistinguishable from a leaked configured token.
#[tokio::test]
async fn read_scoped_key_is_rejected_on_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "reader".to_string(),
			hash: crate::api::api_keys::sha256_hash("reader-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some("reader-secret"),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"subject": "Hi",
			"text": "hello"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED, "read scope must not send");
	assert_eq!(body["error"]["code"], "unauthenticated");
}

#[tokio::test]
async fn queue_removal_requires_the_write_scope() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "reader".to_string(),
			hash: crate::api::api_keys::sha256_hash("reader-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let (_, page) = request(
		&router(test_state(dir.path(), 1)),
		"GET",
		"/api/v1/queue",
		Some(TOKEN.as_str()),
	)
	.await;
	let id = page["entries"][0]["id"].as_str().expect("id");
	let app = router(test_state(dir.path(), 1));
	let (status, body) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some("reader-secret"),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(body["error"]["code"], "unauthenticated");
}

/// A send-only API key cannot write to `/api/v1/accounts` — scopes are
/// independent (a `send` key is not also a `write` key).
#[tokio::test]
async fn send_scoped_key_is_rejected_on_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "sender".to_string(),
			hash: crate::api::api_keys::sha256_hash("sender-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["send".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some("sender-secret"),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@example.org"],
			"password": fixtures::password()
		})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"send scope must not mutate accounts"
	);
	assert_eq!(body["error"]["code"], "unauthenticated");
}

/// A send-only API key passes the middleware on `POST /api/v1/send`: the
/// acceptance half of the send blast-radius control.
#[tokio::test]
async fn send_scoped_key_is_admitted_on_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "sender".to_string(),
			hash: crate::api::api_keys::sha256_hash("sender-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["send".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some("sender-secret"),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"subject": "Hi",
			"text": "hello"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "send scope admits a /send POST");
}
