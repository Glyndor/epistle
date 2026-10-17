//! The attachment policy on `/api/v1/send`: a disguised file is refused
//! with `attachment_refused` and nothing is queued.

use std::sync::Arc;

use base64::Engine as _;

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use crate::antispam::attachments::policy::Policy;
use crate::antispam::submission_scan::ScanningSink;
use crate::config::{AttachmentMode, Attachments};
use crate::storage::{FsSpool, SplitDelivery};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn api_send_with_a_disguised_attachment_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
	let split = SplitDelivery::new(dir.path(), directory).expect("sink");
	let section = Attachments {
		mode: AttachmentMode::Reject,
		..Attachments::default()
	};
	let policy = Arc::new(Policy::from_config(&section, 1 << 20).expect("policy"));
	let sink =
		ScanningSink::wrap_with_attachments(true, Arc::new(split), None, Some(policy), None, None)
			.expect("sink");
	let app = router(test_state(dir.path(), 0).with_outbound(sink));
	let exe = base64::engine::general_purpose::STANDARD.encode(b"MZ\x90\x00\x03\x00\x00\x00");
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({
			"from": "alice@example.org",
			"to": ["bob@elsewhere.example"],
			"subject": "s",
			"text": "see attached",
			"attachments": [{"name": "photo.jpg", "content_type": "image/jpeg", "data": exe}],
		})),
	)
	.await;
	assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
	assert_eq!(body["error"]["code"], "attachment_refused", "{body}");
	assert_eq!(
		body["error"]["message"],
		"The message was rejected: attachment type not accepted (executable-content,type-mismatch).",
		"{body}"
	);
	let queued = FsSpool::open(dir.path())
		.expect("spool")
		.list()
		.expect("list");
	assert!(queued.is_empty(), "nothing queued");
}
