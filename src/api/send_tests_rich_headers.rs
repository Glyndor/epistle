//! The headers `POST /api/v1/send` accepts beyond From, To and Subject, the
//! ones it refuses to let a caller set.

use super::send_tests_rich::{queued, send};
use axum::http::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn the_bounded_extra_headers_are_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({
			"subject": "Grüße aus Köln",
			"reply_to": "support@example.org",
			"sender": "alice@example.org",
			"in_reply_to": "<a1@elsewhere.example>",
			"references": "<a0@elsewhere.example> <a1@elsewhere.example>",
			"importance": "high",
			"list_unsubscribe": ["mailto:unsub@example.org", "https://example.org/u/1"],
			"list_unsubscribe_post": true,
			"auto_submitted": "auto-generated",
			"feedback_id": "c1:newsletter:example",
			"headers": {"X-Campaign": "autumn"},
			"text": "x",
		}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (_, raw) = queued(dir.path());
	let text = String::from_utf8_lossy(&raw).replace("\r\n ", " ");
	for line in [
		"Subject: =?UTF-8?B?",
		"Reply-To: support@example.org\r\n",
		"Sender: alice@example.org\r\n",
		"In-Reply-To: <a1@elsewhere.example>\r\n",
		"References: <a0@elsewhere.example> <a1@elsewhere.example>\r\n",
		"Importance: high\r\n",
		"X-Priority: 1 (Highest)\r\n",
		"List-Unsubscribe: <mailto:unsub@example.org>, <https://example.org/u/1>\r\n",
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
		"Auto-Submitted: auto-generated\r\n",
		"Feedback-ID: c1:newsletter:example\r\n",
		"X-Campaign: autumn\r\n",
	] {
		assert!(text.contains(line), "missing {line:?} in {text}");
	}
}

/// One field set to `value`, sent; the status and the error code.
async fn refused(field: &str, value: Value) -> (StatusCode, Value) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(dir.path(), json!({ field: value, "text": "x" })).await;
	(status, body["error"]["code"].clone())
}

#[tokio::test]
async fn headers_that_would_override_the_message_are_refused() {
	for name in [
		"From",
		"To",
		"Date",
		"Message-ID",
		"DKIM-Signature",
		"Content-Type",
		"MIME-Version",
		"Bcc",
		"X-Priority",
	] {
		let (status, code) = refused("headers", json!({ name: "v" })).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{name} must be refused");
		assert_eq!(code, "invalid_input", "{name}");
	}
}

#[tokio::test]
async fn malformed_extra_headers_are_refused() {
	for (field, value) in [
		("importance", json!("urgent")),
		("auto_submitted", json!("sometimes")),
		("in_reply_to", json!("not-a-message-id")),
		("references", json!("<a@b> plain")),
		("list_unsubscribe", json!(["http://example.org/u"])),
		("list_unsubscribe", json!(["https://example.org/<u>"])),
	] {
		let (status, code) = refused(field, value.clone()).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{field} = {value}");
		assert_eq!(code, "invalid_input", "{field}");
	}
	// One-click unsubscribe (RFC 8058) needs an HTTPS URL to post to.
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({"list_unsubscribe": ["mailto:u@example.org"], "list_unsubscribe_post": true}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn a_sender_the_account_does_not_own_is_refused() {
	let (status, code) = refused("sender", json!("mallory@elsewhere.example")).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert_eq!(code, "forbidden_from");
}
