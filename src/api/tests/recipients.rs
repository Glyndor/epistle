//! `max_recipients` through the REST send endpoint and JMAP
//! `EmailSubmission/set`: both follow the cap the operator set, the one the
//! SMTP listeners enforce.

use super::base::{TOKEN, request_with_body, test_state};
use super::jmap_f::{seed_email, submission_request};
use super::router;
use axum::http::StatusCode;

fn recipients(count: usize) -> Vec<String> {
	(0..count)
		.map(|index| format!("r{index}@elsewhere.example"))
		.collect()
}

async fn send(app: &axum::Router, count: usize) -> (StatusCode, serde_json::Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(serde_json::json!({
			"from": "alice@example.org",
			"to": recipients(count),
			"subject": "Hi",
			"text": "hello"
		})),
	)
	.await
}

#[tokio::test]
async fn rest_send_takes_as_many_recipients_as_the_cap_and_refuses_one_more() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_max_recipients(500));
	let (status, body) = send(&app, 500).await;
	assert_eq!(status, StatusCode::OK, "500 recipients fit a cap of 500");
	assert!(body["queued"].as_str().is_some(), "{body}");
	let (status, body) = send(&app, 501).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"]["code"], "invalid_input");
	assert_eq!(body["error"]["message"], "Too many recipients.");
}

#[tokio::test]
async fn rest_send_keeps_one_hundred_without_the_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	assert_eq!(send(&app, 100).await.0, StatusCode::OK);
	assert_eq!(send(&app, 101).await.0, StatusCode::BAD_REQUEST);
}

async fn submit(app: &axum::Router, dir: &std::path::Path, count: usize) -> serde_json::Value {
	let rcpts = recipients(count);
	let email_id = seed_email(dir, &rcpts);
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(submission_request(&email_id, &rcpts)),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

#[tokio::test]
async fn jmap_submission_takes_as_many_recipients_as_the_cap_and_refuses_one_more() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_max_recipients(500));
	let response = submit(&app, dir.path(), 500).await;
	assert!(
		response["created"]["s1"].is_object(),
		"500 recipients fit a cap of 500: {response}"
	);
	let response = submit(&app, dir.path(), 501).await;
	assert_eq!(response["notCreated"]["s1"]["type"], "tooManyRecipients");
	assert_eq!(
		response["notCreated"]["s1"]["description"],
		"too many recipients (501 > 500)"
	);
}
