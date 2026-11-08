//! An address is one lowercase string on the envelope whatever case the
//! client typed, through `/api/v1/send` and through JMAP `EmailSubmission/set`.
//! The headers of a stored draft stay as their author wrote them.

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use crate::storage::FsSpool;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn api_send_queues_the_sender_and_every_recipient_in_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({
			"from": "Alice@Example.ORG",
			"to": ["Bob.Smith@Elsewhere.Example"],
			"cc": ["CAROL@elsewhere.example"],
			"reply_to": "Reply@Elsewhere.Example",
			"bcc": ["Dave+Tag@Elsewhere.Example"],
			"text": "x"
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	let head = String::from_utf8_lossy(&entry.data);
	let head = head.split("\r\n\r\n").next().unwrap_or_default();
	for line in [
		"From: alice@example.org",
		"To: bob.smith@elsewhere.example",
		"Cc: carol@elsewhere.example",
		"Reply-To: reply@elsewhere.example",
	] {
		assert!(head.contains(line), "{line:?} not in {head}");
	}
	assert_eq!(entry.envelope.reverse_path, "alice@example.org");
	assert_eq!(
		entry.envelope.recipients,
		[
			"bob.smith@elsewhere.example",
			"carol@elsewhere.example",
			"dave+tag@elsewhere.example"
		]
	);
}

#[tokio::test]
async fn jmap_submission_queues_an_explicit_envelope_in_lowercase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		"From: Alice@Example.ORG\r\nTo: Bob <BOB@elsewhere.example>\r\nSubject: s\r\n\r\nbody\r\n",
	)
	.expect("write draft");
	let req = json!({"using": ["urn:ietf:params:jmap:submission"], "methodCalls": [[
		"EmailSubmission/set",
		{"accountId": "alice", "create": {"s": {
			"emailId": id.to_string(),
			"envelope": {
				"mailFrom": {"email": "ALICE@example.org"},
				"rcptTo": [{"email": "Bob@Elsewhere.Example"}]
			}
		}}},
		"c"
	]]});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert_eq!(entry.envelope.reverse_path, "alice@example.org");
	assert_eq!(entry.envelope.recipients, ["bob@elsewhere.example"]);
}

#[tokio::test]
async fn jmap_submission_without_an_envelope_lowercases_the_header_addresses_only_on_the_envelope()
{
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		"From: Alice@Example.ORG\r\nTo: Bob <BOB@elsewhere.example>\r\nSubject: s\r\n\r\nbody\r\n",
	)
	.expect("write draft");
	let req = json!({"using": ["urn:ietf:params:jmap:submission"], "methodCalls": [[
		"EmailSubmission/set",
		{"accountId": "alice", "create": {"s": {"emailId": id.to_string()}}},
		"c"
	]]});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert_eq!(entry.envelope.reverse_path, "alice@example.org");
	assert_eq!(entry.envelope.recipients, ["bob@elsewhere.example"]);
}
