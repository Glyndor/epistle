//! REST account and send endpoints: a refused address says which rule it
//! breaks, in a short message.

use super::tests::{TOKEN, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;

async fn create(app: &Router, name: &str, address: &str) -> (StatusCode, serde_json::Value) {
	let body = serde_json::json!({
		"name": name,
		"addresses": [address],
		"password": "Correct-Horse-Battery-9",
	});
	request_with_body(
		app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(body),
	)
	.await
}

#[tokio::test]
async fn account_create_names_the_rule_an_address_breaks() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let long = format!("{}@example.org", "a".repeat(65));
	let (status, body) = create(&app, "bob", &long).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(
		body["error"]["message"],
		"local part is 65 characters; the maximum is 64 (RFC 5321)"
	);
	let (status, body) = create(&app, "bob", "bob@example.com").await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(
		body["error"]["message"],
		"example.com is not a domain this server handles"
	);
}

#[tokio::test]
async fn send_names_the_rule_a_recipient_breaks() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let body = serde_json::json!({
		"from": "alice@example.org",
		"to": ["a..b@elsewhere.example"],
		"subject": "s",
		"text": "t",
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(body),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(
		body["error"]["message"],
		"Invalid recipient address: consecutive dots in the local part."
	);
}

#[tokio::test]
async fn account_create_stores_and_lists_the_lowercase_form() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = create(&app, "Bob", "Bob.Smith@Example.ORG").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["created"], "bob");
	let (status, body) =
		super::tests::request(&app, "GET", "/api/v1/accounts", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	let bob = body["accounts"]
		.as_array()
		.expect("accounts")
		.iter()
		.find(|account| account["name"] == "bob")
		.expect("bob is listed under the lowercase name");
	assert_eq!(
		bob["addresses"],
		serde_json::json!(["bob.smith@example.org"])
	);
}
