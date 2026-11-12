//! Final delivery of what the API sends to a local recipient: the copy in
//! the mailbox starts with `Return-Path` (RFC 5321 section 4.4) and
//! `Delivered-To`, on
//! `/api/v1/send` and on JMAP `EmailSubmission/set` alike.

use super::base::{TOKEN, request_with_body};
use super::router;
use super::send_outbound::{alice_messages, routed_state};
use axum::http::StatusCode;
use serde_json::{Value, json};

/// alice's stored messages that final delivery wrote (a draft has no
/// `Return-Path`).
fn delivered(dir: &std::path::Path) -> Vec<String> {
	alice_messages(dir)
		.into_iter()
		.map(|raw| String::from_utf8(raw).expect("utf8"))
		.filter(|text| text.to_ascii_lowercase().contains("return-path:"))
		.collect()
}

#[tokio::test]
async fn api_send_to_a_local_recipient_stores_the_return_path_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({"from": "alice@example.org", "to": ["alice@example.org"], "text": "x"})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let copies = delivered(dir.path());
	assert_eq!(copies.len(), 1);
	assert!(
		copies[0]
			.starts_with("Return-Path: <alice@example.org>\r\nDelivered-To: alice@example.org\r\n"),
		"{}",
		copies[0]
	);
}

#[tokio::test]
async fn jmap_submission_to_a_local_recipient_stores_the_return_path_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		"Return-Path: <forged@attacker.example>\r\nFrom: alice@example.org\r\n\
		 To: alice@example.org\r\nSubject: s\r\n\r\nbody\r\n",
	)
	.expect("draft");
	let call = json!(["EmailSubmission/set",
		{"accountId": "alice", "create": {"s": {"emailId": id.to_string(), "envelope": {
			"mailFrom": {"email": "alice@example.org"},
			"rcptTo": [{"email": "alice@example.org"}]}}}}, "c"]);
	let request = json!({"using": ["urn:ietf:params:jmap:submission"], "methodCalls": [call]});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let copies = delivered(dir.path());
	assert_eq!(
		copies.len(),
		3,
		"the draft, the delivered copy, and the Sent copy"
	);
	let stamped: Vec<&String> = copies
		.iter()
		.filter(|copy| {
			copy.starts_with(
				"Return-Path: <alice@example.org>\r\nDelivered-To: alice@example.org\r\n",
			)
		})
		.collect();
	assert_eq!(stamped.len(), 1, "{copies:?}");
	assert!(!stamped[0].contains("forged@"), "{}", stamped[0]);
}

#[tokio::test]
async fn jmap_submission_keeps_tls_required_for_the_queue() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		"TLS-Required: No\r\nFrom: alice@example.org\r\nTo: bob@elsewhere.example\r\n\
		 Subject: s\r\n\r\nbody\r\n",
	)
	.expect("draft");
	let call = json!(["EmailSubmission/set",
		{"accountId": "alice", "create": {"s": {"emailId": id.to_string(), "envelope": {
			"mailFrom": {"email": "alice@example.org"},
			"rcptTo": [{"email": "bob@elsewhere.example"}]}}}}, "c"]);
	let request = json!({"using": ["urn:ietf:params:jmap:submission"], "methodCalls": [call]});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert!(String::from_utf8_lossy(&entry.data).contains("TLS-Required: No\r\n"));
}

/// Store `raw` as alice's draft and submit it without an envelope; the
/// method response.
async fn submit_without_envelope(app: &axum::Router, dir: &std::path::Path, raw: &str) -> Value {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("draft");
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

#[tokio::test]
async fn jmap_submission_without_an_envelope_sends_from_the_from_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let response = submit_without_envelope(
		&app,
		dir.path(),
		"From: Alice <alice@example.org>\r\nTo: bob@elsewhere.example, alice@example.org\r\n\
		 Subject: s\r\n\r\nbody\r\n",
	)
	.await;
	assert!(response["created"]["s"]["id"].is_string(), "{response}");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert_eq!(entry.envelope.reverse_path, "alice@example.org");
	let local: Vec<String> = delivered(dir.path())
		.into_iter()
		.filter(|copy| copy.starts_with("Return-Path:"))
		.collect();
	assert_eq!(local.len(), 1, "{local:?}");
	assert!(
		local[0].starts_with("Return-Path: <alice@example.org>\r\n"),
		"{}",
		local[0]
	);
}

#[tokio::test]
async fn jmap_submission_without_an_envelope_takes_the_sender_header_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(routed_state(dir.path()));
	let response = submit_without_envelope(
		&app,
		dir.path(),
		"Sender: other@example.org\r\nFrom: alice@example.org\r\nTo: bob@elsewhere.example\r\n\
		 Subject: s\r\n\r\nbody\r\n",
	)
	.await;
	assert_eq!(
		response["notCreated"]["s"]["type"], "forbiddenFrom",
		"the Sender is the MAIL FROM, and alice does not own it: {response}"
	);
}
