//! The antivirus on mail the API sends: `/api/v1/send` and JMAP
//! `EmailSubmission/set` reach the routing sink through the same submission
//! path as SMTP, so a message carrying a virus is refused on both, for local
//! and remote recipients alike, and nothing is stored or queued.

use std::sync::Arc;

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::send_outbound::alice_messages;
use super::state::ApiState;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::clamd::tests::fake::{FakeClamd, SIGNATURE, eicar};
use crate::antispam::submission_scan::ScanningSink;
use crate::storage::{FsSpool, SplitDelivery};
use axum::http::StatusCode;
use serde_json::{Value, json};

/// The server's routing sink, wrapped in the scan when `enabled`.
fn scanned_state(dir: &std::path::Path, enabled: bool, clamd: &FakeClamd) -> ApiState {
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
	let split = SplitDelivery::new(dir, directory).expect("sink");
	let hook = Arc::new(ClamdHook::new(clamd.socket.clone()));
	let sink = ScanningSink::wrap(enabled, Arc::new(split), Some(hook), None, None).expect("sink");
	test_state(dir, 0).with_outbound(sink)
}

pub(in super::super) fn queued(dir: &std::path::Path) -> usize {
	FsSpool::open(dir)
		.expect("spool")
		.list()
		.expect("list")
		.len()
}

pub(in super::super) async fn api_send(
	app: &axum::Router,
	to: &str,
	text: &str,
) -> (StatusCode, Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({"from": "alice@example.org", "to": [to], "subject": "s", "text": text})),
	)
	.await
}

#[tokio::test]
async fn api_send_with_a_virus_is_refused_for_remote_and_local_recipients() {
	let clamd = FakeClamd::start();
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scanned_state(dir.path(), true, &clamd));
	for to in ["bob@elsewhere.example", "alice@example.org"] {
		let (status, body) = api_send(&app, to, &eicar()).await;
		assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
		assert_eq!(body["error"]["code"], "virus_detected", "{body}");
		let message = body["error"]["message"].as_str().unwrap_or_default();
		assert!(message.contains(SIGNATURE), "{body}");
	}
	assert_eq!(queued(dir.path()), 0, "nothing queued");
	assert!(alice_messages(dir.path()).is_empty(), "nothing stored");
}

#[tokio::test]
async fn api_send_with_the_scan_off_or_a_clean_message_goes_through() {
	let clamd = FakeClamd::start();
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scanned_state(dir.path(), false, &clamd));
	let (status, body) = api_send(&app, "bob@elsewhere.example", &eicar()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(clamd.scans(), 0);
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scanned_state(dir.path(), true, &clamd));
	let (status, body) = api_send(&app, "bob@elsewhere.example", "hello").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(clamd.scans(), 1);
	assert_eq!(queued(dir.path()), 1);
}

/// Store `raw` as a draft of alice and submit it over JMAP; the response.
pub(in super::super) async fn jmap_submit(
	app: &axum::Router,
	dir: &std::path::Path,
	raw: &str,
) -> Value {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("write draft");
	let call = json!(["EmailSubmission/set",
		{"accountId": "alice", "create": {"s": {"emailId": id.to_string()}}}, "c"]);
	let request = json!({"using": ["urn:ietf:params:jmap:submission"], "methodCalls": [call]});
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

pub(in super::super) fn draft(body: &str) -> String {
	format!("From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: s\r\n\r\n{body}\r\n")
}

#[tokio::test]
async fn jmap_submission_with_a_virus_is_forbidden_to_send() {
	let clamd = FakeClamd::start();
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scanned_state(dir.path(), true, &clamd));
	let response = jmap_submit(&app, dir.path(), &draft(&eicar())).await;
	let refusal = &response["notCreated"]["s"];
	assert_eq!(refusal["type"], "forbiddenToSend", "{response}");
	let description = refusal["description"].as_str().unwrap_or_default();
	assert!(description.contains(SIGNATURE), "{response}");
	assert_eq!(queued(dir.path()), 0);
}

#[tokio::test]
async fn jmap_submission_with_the_scan_off_is_sent() {
	let clamd = FakeClamd::start();
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scanned_state(dir.path(), false, &clamd));
	let response = jmap_submit(&app, dir.path(), &draft(&eicar())).await;
	assert!(response["created"]["s"]["id"].is_string(), "{response}");
	assert_eq!(queued(dir.path()), 1);
}
