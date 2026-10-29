//! The single-label domain rule at SCIM.
//!
//! A domain of one label (`localhost`, `intranet`) is legal by RFC 5321
//! syntax but cannot be delivered on the public internet, so SCIM refuses a
//! user that carries one, in the same words every other surface uses.

use super::base::{SCIM_KEY_SECRET, app, build_state, send_with_headers};
use axum::http::StatusCode;

/// `POST /scim/v2/Users` refuses an address whose domain has one label.
#[tokio::test]
async fn a_user_with_a_single_label_domain_is_refused() {
	let (_dir, state) = build_state();
	let (status, body, _headers) = send_with_headers(
		&app(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&serde_json::json!({
			"userName": "bob",
			"active": true,
			"emails": [{"value": "bob@localhost", "type": "work", "primary": true}],
			"password": "Correct-Horse-Battery-9",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let detail = body["detail"].as_str().expect("detail");
	assert!(
		detail.contains("needs at least one dot"),
		"the refusal names the rule: {detail}"
	);
	assert!(
		detail.contains("localhost"),
		"the refusal names the domain: {detail}"
	);
}

/// The user is not created: the refusal happens before the write.
#[tokio::test]
async fn a_refused_user_is_not_created() {
	let (_dir, state) = build_state();
	let (status, _body, _headers) = send_with_headers(
		&app(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&serde_json::json!({
			"userName": "bob",
			"active": true,
			"emails": [{"value": "bob@intranet", "type": "work", "primary": true}],
			"password": "Correct-Horse-Battery-9",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	let (status, body, _headers) = send_with_headers(
		&app(state.clone()),
		"GET",
		"/scim/v2/Users/bob",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
