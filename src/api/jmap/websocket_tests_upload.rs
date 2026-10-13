//! An Email with an uploaded attachment, created and sent over the
//! WebSocket: the frame's uploads are read before it is dispatched, as on
//! `POST /jmap/api`.

use mail_parser::{MessageParser, MimeHeaders};
use serde_json::{Value, json};

use super::{PushState, handle_frame};
use crate::api::Principal;
use crate::api::router;
use crate::api::tests::{TOKEN, test_state};
use crate::storage::FsSpool;

async fn frame(state: &crate::api::state::ApiState, calls: Value) -> Value {
	let text = json!({"@type": "Request", "using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": calls})
	.to_string();
	let principal = Principal::Admin { credential: None };
	let replies = handle_frame(state, &principal, &text, &mut PushState::default()).await;
	assert_eq!(replies.len(), 1, "{replies:?}");
	let reply: Value = serde_json::from_str(&replies[0]).expect("json");
	reply["methodResponses"][0][1].clone()
}

#[tokio::test]
async fn an_email_with_an_uploaded_attachment_is_sent_over_the_websocket() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let state = test_state(dir.path(), 0);
	let app = router(state.clone());
	let data: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
	let blob = upload(&app, &data).await;
	let created = frame(
		&state,
		json!([["Email/set", {"accountId": "alice", "create": {"e": {
			"mailboxIds": {"INBOX": true},
			"from": [{"email": "alice@example.org"}],
			"to": [{"email": "bob@elsewhere.example"}],
			"subject": "over the socket",
			"textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": "see attached"}},
			"attachments": [{"blobId": blob, "type": "application/octet-stream", "name": "a.bin"}],
		}}}, "c1"]]),
	)
	.await;
	let email = created["created"]["e"]["id"]
		.as_str()
		.unwrap_or_else(|| panic!("created over the socket: {created}"))
		.to_string();
	let submitted = frame(
		&state,
		json!([["EmailSubmission/set", {"accountId": "alice",
			"create": {"s": {"emailId": email}}}, "c2"]]),
	)
	.await;
	assert!(submitted["created"]["s"]["id"].is_string(), "{submitted}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("queued");
	let message = MessageParser::default().parse(&entry.data).expect("parse");
	let attachment = message.attachment(0).expect("attachment");
	assert_eq!(attachment.attachment_name(), Some("a.bin"));
	assert_eq!(
		attachment.contents(),
		data.as_slice(),
		"the uploaded bytes went out"
	);
}

async fn upload(app: &axum::Router, data: &[u8]) -> String {
	use axum::body::Body;
	use axum::http::{Request, header};
	use tower::ServiceExt;
	let request = Request::builder()
		.method("POST")
		.uri("/jmap/upload/alice")
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.body(Body::from(data.to_vec()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let body: Value = serde_json::from_slice(&bytes).expect("json");
	body["blobId"].as_str().expect("blobId").to_string()
}
