//! `POST /api/v1/send` and JMAP `EmailSubmission/set` take the same outbound
//! path as SMTP submission: remote mail is DKIM-signed for the sender's
//! domain and queued under the id the caller gets back, and a local
//! recipient is delivered to the mailbox instead of the queue.

use std::sync::Arc;

use super::router;
use super::state::ApiState;
use super::tests::{TOKEN, request_with_body, test_state};
use crate::dkim::test_support::signature_fields;
use crate::dkim::{ReloadableSigner, Signer};
use crate::storage::{FsSpool, SplitDelivery};
use axum::http::StatusCode;
use serde_json::json;

/// The test state with the routing sink the server builds, signing with a
/// fresh key under selector `sel`.
pub(super) fn routed_state(dir: &std::path::Path) -> ApiState {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let key_file = dir.join("dkim.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = ReloadableSigner::new(Arc::new(Signer::load("sel", &key_file).expect("load")));
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
	let split = SplitDelivery::new(dir, directory)
		.expect("sink")
		.with_signer(signer);
	test_state(dir, 0).with_outbound(Arc::new(split))
}

/// Every stored message file under alice's mail, whatever the mailbox.
pub(super) fn alice_messages(dir: &std::path::Path) -> Vec<Vec<u8>> {
	let mut found = Vec::new();
	let mut pending = vec![dir.join("accounts").join("alice")];
	while let Some(path) = pending.pop() {
		let Ok(entries) = std::fs::read_dir(&path) else {
			continue;
		};
		for entry in entries.flatten() {
			let path = entry.path();
			if path.is_dir() {
				pending.push(path);
			} else if path.extension().is_some_and(|ext| ext == "eml") {
				found.push(std::fs::read(&path).expect("read message"));
			}
		}
	}
	found
}

async fn api_send(app: &axum::Router, to: &str) -> serde_json::Value {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(
			json!({"from": "alice@example.org", "to": [to], "subject": "Routed", "text": "hello"}),
		),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body
}

#[tokio::test]
async fn api_send_to_a_remote_recipient_is_signed_and_queued_under_the_returned_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let body = api_send(&app, "bob@elsewhere.example").await;
	let id = uuid::Uuid::parse_str(body["queued"].as_str().expect("queued id")).expect("uuid");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert_eq!(
		spool.list().expect("list"),
		vec![id],
		"one entry, the returned id"
	);
	let entry = spool.load(id).expect("queued entry");
	assert_eq!(
		signature_fields(&entry.data),
		vec![("sel".into(), "example.org".into(), "ed25519-sha256".into())],
		"API mail must leave with a DKIM-Signature for the From domain"
	);
}

#[tokio::test]
async fn api_send_to_a_local_recipient_is_delivered_not_queued() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let body = api_send(&app, "alice@example.org").await;
	assert!(body["queued"].is_string(), "{body}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert_eq!(
		spool.list().expect("list").len(),
		0,
		"local mail is not queued"
	);
	let delivered = alice_messages(dir.path());
	// Two copies on disk: the inbox delivery and the Sent folder
	// the saver keeps by default. The Sent copy is an additional
	// outcome of the save-sent feature, not a regression.
	assert_eq!(
		delivered.len(),
		2,
		"delivered to the local mailbox and to Sent"
	);
	assert!(
		delivered[0].windows(16).any(|w| w == b"Subject: Routed\r"),
		"the delivered copy is the sent message"
	);
}

/// Store a draft for alice and submit it to `to` through JMAP.
async fn jmap_submit(dir: &std::path::Path, app: &axum::Router, to: &str) -> serde_json::Value {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let email = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{email}.eml")),
		format!("From: alice@example.org\r\nTo: {to}\r\nSubject: Drafted\r\n\r\nbody\r\n"),
	)
	.expect("write draft");
	let req = json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": email.to_string(),
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": to}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1]["created"]["s1"].clone()
}

#[tokio::test]
async fn jmap_submission_to_a_remote_recipient_is_signed_and_queued_under_its_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let created = jmap_submit(dir.path(), &app, "bob@elsewhere.example").await;
	let id = uuid::Uuid::parse_str(created["id"].as_str().expect("submission id")).expect("uuid");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert_eq!(
		spool.list().expect("list"),
		vec![id],
		"one entry, the submission id"
	);
	let entry = spool.load(id).expect("queued entry");
	assert_eq!(
		signature_fields(&entry.data),
		vec![("sel".into(), "example.org".into(), "ed25519-sha256".into())],
		"JMAP mail must leave with a DKIM-Signature for the From domain"
	);
}

#[tokio::test]
async fn jmap_submission_to_a_local_recipient_is_delivered_not_queued() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let created = jmap_submit(dir.path(), &app, "alice@example.org").await;
	assert!(created["id"].is_string(), "{created}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert_eq!(
		spool.list().expect("list").len(),
		0,
		"local mail is not queued"
	);
	assert_eq!(
		alice_messages(dir.path()).len(),
		2,
		"the draft plus the delivered copy"
	);
}
