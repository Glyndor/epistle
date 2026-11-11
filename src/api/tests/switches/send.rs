//! `POST /api/v1/send` under the send switch.

use axum::http::StatusCode;

use super::super::base::{TOKEN, request_with_body};
use super::support::{OFF, ON, app, secret};

fn body(from: &str) -> serde_json::Value {
	serde_json::json!({
		"from": from, "to": ["dest@remote.example"], "subject": "hi", "text": "hello",
	})
}

#[tokio::test]
async fn a_key_bound_to_an_account_with_sending_off_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, response) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(&secret(OFF)),
		Some(body("app@example.org")),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
	assert_eq!(response["error"]["code"], "sending_off");
}

#[tokio::test]
async fn the_admin_token_cannot_send_as_such_an_account_either() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, response) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(body("app@example.org")),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
	assert_eq!(response["error"]["code"], "sending_off");
}

#[tokio::test]
async fn the_refusal_does_not_depend_on_the_sender_the_key_names() {
	// A bound key acts for its own account whatever `from` says, so naming
	// another account's address does not get round the switch.
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, response) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(&secret(OFF)),
		Some(body("bob@example.org")),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
	assert_eq!(response["error"]["code"], "sending_off");
}

#[tokio::test]
async fn an_account_beside_it_still_sends() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, response) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(&secret(ON)),
		Some(body("bob@example.org")),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{response}");
}
