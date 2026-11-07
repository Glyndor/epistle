//! The single-label domain rule at the management API.
//!
//! A domain of one label (`localhost`, `intranet`) is legal by RFC 5321
//! syntax but cannot be delivered on the public internet, so the API
//! refuses an account that carries one, in the same words every other
//! surface uses.

use super::base::{TOKEN, request, request_with_body, test_state};
use super::*;
use crate::test_fixtures as fixtures;
use axum::http::StatusCode;

/// `POST /api/v1/accounts` refuses an address whose domain has one label.
#[tokio::test]
async fn an_account_with_a_single_label_domain_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@localhost"],
			"password": fixtures::password(),
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let message = body["error"]["message"].as_str().expect("message");
	assert!(
		message.contains("needs at least one dot"),
		"the refusal names the rule: {message}"
	);
	assert!(
		message.contains("localhost"),
		"the refusal names the domain: {message}"
	);
}

/// The account is not created: the refusal happens before the write.
#[tokio::test]
async fn a_refused_account_is_not_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"name": "bob",
			"addresses": ["bob@intranet"],
			"password": fixtures::password(),
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	let (status, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	let accounts = body["accounts"].as_array().expect("accounts");
	assert!(
		accounts.iter().all(|account| account["name"] != "bob"),
		"the refused account must not exist"
	);
}
