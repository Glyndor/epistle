//! The submission endpoint the operator sends through.

use super::base::{TOKEN, request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;

#[tokio::test]
async fn send_enqueues_and_validates() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	// A valid request enqueues the message.
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"subject": "Hi",
			"text": "hello"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(body["queued"].as_str().is_some(), "{body}");
	let (_, status_body) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(status_body["queue_size"], 1);

	// Empty recipients, CR/LF header injection, a bad address, and an over-long
	// recipient list (> DEFAULT_MAX_RECIPIENTS) are all rejected.
	let many: Vec<String> = (0..200).map(|i| format!("r{i}@x.example")).collect();
	for bad in [
		serde_json::json!({"from": "alice@example.org", "to": []}),
		serde_json::json!({"from": "alice@example.org", "to": ["b@x.example"], "subject": "x\r\nBcc: evil@x"}),
		serde_json::json!({"from": "not-an-address", "to": ["b@x.example"]}),
		serde_json::json!({"from": "alice@example.org", "to": many}),
	] {
		let (status, body) = request_with_body(
			&app,
			"POST",
			"/api/v1/send",
			Some(TOKEN.as_str()),
			Some(bad),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST);
		assert_eq!(body["error"]["code"], "invalid_input");
	}
}
