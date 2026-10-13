//! Bcc never reaches what is sent: JMAP `EmailSubmission/set` strips the
//! header of the stored draft (RFC 8621 section 7.5) and keeps the Bcc
//! recipients on the envelope; `/api/v1/send` never writes one; JMAP
//! `Email/set` stores `bcc` on the draft only.

use super::router;
use super::send_tests_outbound::{alice_messages, routed_state};
use super::tests::{TOKEN, request_with_body, test_state};
use crate::storage::FsSpool;
use axum::http::StatusCode;
use serde_json::{Value, json};

const DRAFT: &str = "From: alice@example.org\r\nTo: Bob <bob@elsewhere.example>\r\n\
	Cc: carol@elsewhere.example\r\nBcc: hidden@elsewhere.example,\r\n other@elsewhere.example\r\n\
	Subject: s\r\n\r\nbody\r\n";

/// The header block of `data`, lowercased.
fn headers(data: &[u8]) -> String {
	let text = String::from_utf8_lossy(data).to_ascii_lowercase();
	text.split("\r\n\r\n")
		.next()
		.unwrap_or_default()
		.to_string()
}

async fn jmap(app: &axum::Router, call: Value) -> Value {
	let req = json!({"using": ["urn:ietf:params:jmap:submission"], "methodCalls": [call]});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

/// Store `raw` as a draft of alice; its id.
fn draft(dir: &std::path::Path, raw: &str) -> String {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("write draft");
	id.to_string()
}

async fn submit(app: &axum::Router, email: &str, envelope: Option<Value>) -> Value {
	let mut submission = json!({"emailId": email});
	if let Some(envelope) = envelope {
		submission["envelope"] = envelope;
	}
	jmap(
		app,
		json!(["EmailSubmission/set", {"accountId": "alice", "create": {"s": submission}}, "c"]),
	)
	.await
}

#[tokio::test]
async fn jmap_submission_strips_bcc_and_sends_to_every_header_recipient() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let response = submit(&app, &draft(dir.path(), DRAFT), None).await;
	assert!(response["created"]["s"]["id"].is_string(), "{response}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert_eq!(
		entry.envelope.recipients,
		[
			"bob@elsewhere.example",
			"carol@elsewhere.example",
			"hidden@elsewhere.example",
			"other@elsewhere.example"
		],
		"without an envelope, To, Cc and Bcc are the recipients"
	);
	let block = headers(&entry.data);
	assert!(
		!block.contains("\nbcc:") && !block.starts_with("bcc:"),
		"{block}"
	);
	assert!(
		!block.contains("hidden@") && !block.contains("other@"),
		"{block}"
	);
}

#[tokio::test]
async fn a_local_bcc_recipient_gets_a_copy_without_the_bcc_header() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let raw = "From: alice@example.org\r\nTo: bob@elsewhere.example\r\n\
		Bcc: alice@example.org\r\nSubject: s\r\n\r\nbody\r\n";
	let envelope = json!({"mailFrom": {"email": "alice@example.org"},
		"rcptTo": [{"email": "bob@elsewhere.example"}, {"email": "alice@example.org"}]});
	let response = submit(&app, &draft(dir.path(), raw), Some(envelope)).await;
	assert!(response["created"]["s"]["id"].is_string(), "{response}");
	let stored = alice_messages(dir.path());
	assert_eq!(stored.len(), 2, "the draft and the delivered copy");
	let with_bcc = stored
		.iter()
		.filter(|m| headers(m).contains("\nbcc:"))
		.count();
	assert_eq!(with_bcc, 1, "only the draft keeps its Bcc");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert!(
		!headers(&entry.data).contains("\nbcc:"),
		"the remote copy has no Bcc"
	);
}

#[tokio::test]
async fn api_send_bcc_to_a_local_recipient_writes_no_bcc_anywhere() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(
			json!({"from": "alice@example.org", "to": ["bob@elsewhere.example"],
			"bcc": ["alice@example.org"], "text": "x"}),
		),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let stored = alice_messages(dir.path());
	assert_eq!(stored.len(), 1, "the Bcc recipient received it");
	assert!(!headers(&stored[0]).contains("bcc:"));
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert_eq!(entry.envelope.recipients, ["bob@elsewhere.example"]);
	assert!(!headers(&entry.data).contains("bcc:"));
}

#[tokio::test]
async fn jmap_email_set_keeps_bcc_on_the_draft_and_submission_drops_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let created = jmap(
		&app,
		json!(["Email/set", {"accountId": "alice", "create": {"e": {
			"mailboxIds": {"INBOX": true},
			"from": [{"email": "alice@example.org"}],
			"to": [{"email": "bob@elsewhere.example"}],
			"bcc": [{"name": "Hidden", "email": "hidden@elsewhere.example"}],
			"subject": "s", "bodyValues": {"0": {"value": "x"}},
		}}}, "c"]),
	)
	.await;
	let id = created["created"]["e"]["id"]
		.as_str()
		.expect("created")
		.to_string();
	let got = jmap(
		&app,
		json!(["Email/get", {"accountId": "alice", "ids": [&id], "properties": ["bcc"]}, "g"]),
	)
	.await;
	assert_eq!(
		got["list"][0]["bcc"],
		json!([{"name": "Hidden", "email": "hidden@elsewhere.example"}]),
		"the draft keeps its Bcc"
	);
	let response = submit(&app, &id, None).await;
	assert!(response["created"]["s"]["id"].is_string(), "{response}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert_eq!(
		entry.envelope.recipients,
		["bob@elsewhere.example", "hidden@elsewhere.example"]
	);
	assert!(
		!headers(&entry.data).contains("hidden@"),
		"nothing sent names the Bcc"
	);
}
