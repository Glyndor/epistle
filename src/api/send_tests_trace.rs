//! Final delivery of what the API sends to a local recipient: the copy in
//! the mailbox starts with `Return-Path` (RFC 5321 section 4.4) and
//! `Delivered-To`, on
//! `/api/v1/send` and on JMAP `EmailSubmission/set` alike.

use super::router;
use super::send_tests_outbound::{alice_messages, routed_state};
use super::tests::{TOKEN, request_with_body};
use axum::http::StatusCode;
use serde_json::json;

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
	assert_eq!(copies.len(), 2, "the draft and the delivered copy");
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
