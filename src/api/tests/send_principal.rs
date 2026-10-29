//! `POST /api/v1/send` acts for the principal: the envelope sender must be
//! owned by an account the credential may act for, the same rule
//! `EmailSubmission/set` applies to `mailFrom`.

use super::base::{TOKEN, request_with_body};
use super::jmap_principal_b::{key, state_with_key};
use super::router;
use axum::http::StatusCode;
use serde_json::json;

const SECRET: &str = "sender-secret";

/// The refusal every unowned or out-of-reach sender gets, whether or not
/// some other account owns the address.
fn forbidden_from() -> serde_json::Value {
	json!({"error": {
		"code": "forbidden_from",
		"message": "The sender address is not owned by an account this credential may act for.",
	}})
}

fn message(from: &str) -> serde_json::Value {
	json!({"from": from, "to": ["someone@elsewhere.example"], "subject": "s", "text": "t"})
}

/// Both confined kinds, each reaching `ann` and not `bob`.
fn confined_keys() -> [(&'static str, crate::api::api_keys::ApiKey); 2] {
	[
		("domains", key(SECRET, &["a.example"], None, None)),
		("account", key(SECRET, &[], Some("ann"), None)),
	]
}

#[tokio::test]
async fn confined_key_sends_from_an_owned_address() {
	for (kind, key) in confined_keys() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(state_with_key(dir.path(), key));
		let (status, body) = request_with_body(
			&app,
			"POST",
			"/api/v1/send",
			Some(SECRET),
			Some(message("ann@a.example")),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{kind} key: {body}");
		assert!(body["queued"].is_string(), "{kind} key: {body}");
	}
}

#[tokio::test]
async fn confined_key_cannot_send_from_a_foreign_or_unowned_address() {
	for (kind, key) in confined_keys() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(state_with_key(dir.path(), key));
		for from in ["bob@b.example", "nobody@a.example", "nobody@b.example"] {
			let (status, body) = request_with_body(
				&app,
				"POST",
				"/api/v1/send",
				Some(SECRET),
				Some(message(from)),
			)
			.await;
			assert_eq!(
				status,
				StatusCode::FORBIDDEN,
				"{kind} key, from {from}: {body}"
			);
			assert_eq!(body, forbidden_from(), "{kind} key, from {from}");
		}
	}
}

#[tokio::test]
async fn configured_token_cannot_send_from_an_address_no_account_owns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_key(dir.path(), key(SECRET, &[], None, None)));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(message("nobody@a.example")),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert_eq!(body, forbidden_from());
}
