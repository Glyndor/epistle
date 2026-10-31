//! The configured `[server] max_message_size` is advertised by the JMAP
//! Session resource, drives the upload route's body limit, and is what
//! the `Email/set` create builder checks before the message lands in the
//! spool. A lowered cap is visible end-to-end: what the client is told
//! and what the server accepts agree.

use super::base::{TOKEN, request};
use super::router;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn configured_max_message_size_advertises_max_size_upload_in_session() {
	let dir = tempfile::tempdir().expect("tempdir");
	let configured = 4 * 1024 * 1024;
	let app = router(super::base::test_state(dir.path(), 0).with_max_message_size(configured));
	let (status, session) = request(&app, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		session["capabilities"]["urn:ietf:params:jmap:core"]["maxSizeUpload"]
			.as_u64()
			.expect("maxSizeUpload"),
		configured as u64,
		"Session resource must advertise the configured [server] max_message_size as maxSizeUpload"
	);
}

#[tokio::test]
async fn configured_max_message_size_advertises_max_size_attachments_in_session() {
	let dir = tempfile::tempdir().expect("tempdir");
	let configured = 8 * 1024 * 1024;
	let app = router(super::base::test_state(dir.path(), 0).with_max_message_size(configured));
	let (status, session) = request(&app, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	let advertised =
		session["capabilities"]["urn:ietf:params:jmap:mail"]["maxSizeAttachmentsPerEmail"]
			.as_u64()
			.expect("maxSizeAttachmentsPerEmail");
	// The advertised value is the configured cap minus the per-message
	// headroom, base64-encoded four-of-three.
	let expected = (configured - crate::api::jmap::limits::ATTACHMENT_HEADROOM) / 78 * 76 / 4 * 3;
	assert_eq!(
		advertised, expected as u64,
		"Session resource must derive maxSizeAttachmentsPerEmail from the configured cap"
	);
}

#[tokio::test]
async fn configured_max_message_size_smaller_than_default_rejects_what_default_admits() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A cap a 1 MiB payload clears by default (default is 25 MiB).
	let small = 64 * 1024;
	let app = router(super::base::test_state(dir.path(), 0).with_max_message_size(small));
	let payload = vec![0u8; 1024 * 1024];
	let (status, body) =
		post_raw_ct(&app, "/jmap/upload/alice", TOKEN.as_str(), None, &payload).await;
	assert_eq!(
		status,
		StatusCode::PAYLOAD_TOO_LARGE,
		"a 1 MiB upload under a 64 KiB cap must be refused at the upload route's body limit"
	);
	assert_eq!(
		body["limit"], "maxSizeUpload",
		"the JMAP limit problem must name maxSizeUpload"
	);
}

/// `Email/set` create refuses to build a message that would exceed the
/// configured `[server] max_message_size`, returning the JMAP
/// `tooLarge` SetError. A lowered cap trips the check where the
/// built-in default would have admitted the body.
#[tokio::test]
async fn email_set_respects_the_configured_message_size_cap() {
	use super::super::jmap_email::jmap_email_create::create;
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(super::base::test_state(dir.path(), 0).with_max_message_size(8 * 1024));
	// Each `=` quoted-prints to three octets; a 4 KiB body of `=`
	// characters builds past the 8 KiB cap. The request itself fits
	// `maxSizeRequest` (10 MiB); only the post-build size trips the cap.
	let text = "=".repeat(4 * 1024);
	let response = create(
		&app,
		serde_json::json!({"textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": text}}}),
	)
	.await;
	let not_created = &response["notCreated"]["e"];
	assert_eq!(
		not_created["type"], "tooLarge",
		"a body whose built message exceeds [server] max_message_size must trigger the JMAP tooLarge SetError, was {response}"
	);
}

/// Inline copy of `tests_e::post_raw_ct`: that helper is private to its
/// file, and this test file's assertions only need to push a sized payload
/// at the upload route with the bearer token. Body parsing mirrors
/// `tests_e`.
async fn post_raw_ct(
	app: &Router,
	path: &str,
	token: &str,
	content_type: Option<&str>,
	body: &[u8],
) -> (StatusCode, serde_json::Value) {
	let mut builder = Request::builder().method("POST").uri(path);
	builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	if let Some(content_type) = content_type {
		builder = builder.header(header::CONTENT_TYPE, content_type);
	}
	let request = builder.body(Body::from(body.to_vec())).expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
		.await
		.expect("body");
	let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(
		|_| serde_json::json!({"raw": String::from_utf8_lossy(&bytes).to_string()}),
	);
	(status, value)
}
