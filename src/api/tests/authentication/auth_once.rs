//! A request compares its bearer against the configured token hash once, in
//! the bearer middleware. That hash may be a legacy argon2id one, so every
//! further comparison (the account-bound gate, the handler resolving the
//! principal, each per-call scope check) would cost another argon2
//! verification on the same request.

use super::super::jmap_state::jmap_principal_b::{key, state_with_key};
use super::base::TOKEN;
use super::router;
use super::state::CONFIGURED_HASH_CHECKS;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

const SECRET: &str = "auth-once-secret";

fn app(dir: &std::path::Path) -> Router {
	router(state_with_key(dir, key(SECRET, &[], None, None)))
}

/// Send `method path` with `body` as `token`, and return the status and how
/// many times the configured hash was checked while serving it.
async fn checks_for(
	app: &Router,
	method: &str,
	path: &str,
	token: &str,
	body: Body,
) -> (StatusCode, usize) {
	CONFIGURED_HASH_CHECKS.with(|checks| checks.set(0));
	let request = Request::builder()
		.method(method)
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.header(header::CONTENT_TYPE, "application/json")
		.body(body)
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, CONFIGURED_HASH_CHECKS.with(std::cell::Cell::get))
}

fn three_calls() -> Body {
	Body::from(
		json!({
			"using": ["urn:ietf:params:jmap:core"],
			"methodCalls": [
				["Mailbox/get", { "accountId": "ann" }, "c1"],
				["Email/query", { "accountId": "ann" }, "c2"],
				["Core/echo", {}, "c3"],
			],
		})
		.to_string(),
	)
}

#[tokio::test]
async fn a_jmap_request_with_the_configured_token_checks_the_hash_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, checks) =
		checks_for(&app, "POST", "/jmap/api", TOKEN.as_str(), three_calls()).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(checks, 1, "configured-hash checks for one request");
}

#[tokio::test]
async fn a_jmap_request_with_an_api_key_never_checks_the_configured_hash() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, checks) = checks_for(&app, "POST", "/jmap/api", SECRET, three_calls()).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		checks, 0,
		"a key is found by its SHA-256 before the configured hash is looked at"
	);
}

#[tokio::test]
async fn an_upload_with_an_api_key_never_checks_the_configured_hash() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, checks) =
		checks_for(&app, "POST", "/jmap/upload/ann", SECRET, Body::from("blob")).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		checks, 0,
		"a key is found by its SHA-256 before the configured hash is looked at"
	);
}

#[tokio::test]
async fn a_management_request_with_an_api_key_never_checks_the_configured_hash() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, checks) = checks_for(&app, "GET", "/api/v1/accounts", SECRET, Body::empty()).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		checks, 0,
		"a key is found by its SHA-256 before the configured hash is looked at"
	);
}
