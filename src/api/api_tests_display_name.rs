//! The REST account endpoints carry the display name: set on create,
//! changed or cleared with `PUT /api/v1/accounts/{name}/display_name`,
//! listed as given, refused with a line break.

use super::tests::{TOKEN, request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;

fn listed(body: &serde_json::Value, name: &str) -> serde_json::Value {
	body["accounts"]
		.as_array()
		.expect("accounts")
		.iter()
		.find(|account| account["name"] == name)
		.expect("listed")["display_name"]
		.clone()
}

async fn put(app: &Router, value: &str) -> (StatusCode, serde_json::Value) {
	let body = serde_json::json!({ "display_name": value });
	request_with_body(
		app,
		"PUT",
		"/api/v1/accounts/bob/display_name",
		Some(TOKEN.as_str()),
		Some(body),
	)
	.await
}

#[tokio::test]
async fn create_set_list_and_clear_a_display_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let create = serde_json::json!({
		"name": "bob",
		"addresses": ["bob@example.org"],
		"password": "Correct-Horse-Battery-9",
		"display_name": "Bob MÜLLER",
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(create),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(listed(&body, "bob"), "Bob MÜLLER");
	assert_eq!(listed(&body, "alice"), serde_json::Value::Null);

	let (status, body) = put(&app, " Robert Müller ").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["display_name"], "Robert Müller");
	let (_, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(listed(&body, "bob"), "Robert Müller");

	let (status, body) = put(&app, "").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["display_name"], serde_json::Value::Null);

	let (status, body) = put(&app, "Bob\r\nBcc: x@example.net").await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(
		body["error"]["message"],
		"the display name must not contain control characters or line breaks"
	);
}
