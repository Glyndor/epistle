//! JMAP `EmailSubmission` tests.

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use axum::http::StatusCode;

#[tokio::test]
async fn jmap_email_submission_queues_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		body["methodResponses"][0][1]["created"]["s1"]["id"].is_string(),
		"{body}"
	);
	let spool_new = dir.path().join("spool").join("new");
	let count = std::fs::read_dir(&spool_new)
		.map(|d| d.count())
		.unwrap_or(0);
	assert!(count >= 1, "expected a spooled message");
}

/// `EmailSubmission/set` must reject a non-empty `envelope.mailFrom.email`
/// that the named `accountId` does not own. Without this guard a bearer
/// token holder can submit outbound mail as any address (RFC 8621 §7.5.2:
/// `forbiddenFrom`).
#[tokio::test]
async fn jmap_email_submission_rejects_unowned_mail_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	// alice tries to send as bob@elsewhere.example — an address no one owns
	// in this test's directory (only alice@example.org is configured).
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "bob@elsewhere.example"},
					"rcptTo": [{"email": "carol@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["notCreated"]["s1"]["type"], "forbiddenFrom",
		"send-as must be rejected with forbiddenFrom: {body}"
	);
}

/// `EmailSubmission/set` must reject a `mailFrom` that does not parse as an
/// address: a malformed envelope value is not a free pass to spoofing.
#[tokio::test]
async fn jmap_email_submission_rejects_malformed_mail_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "not-an-address"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["notCreated"]["s1"]["type"], "invalidEmail",
		"malformed mailFrom must be rejected with invalidEmail: {body}"
	);
}

/// `EmailSubmission/set` must accept a `mailFrom` that is one of the
/// account's configured addresses — the acceptance case that proves the
/// control does not over-reject (paired with the two rejection tests above).
#[tokio::test]
async fn jmap_email_submission_accepts_owned_mail_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	// The case-insensitive variant `ALICE@EXAMPLE.ORG` still matches:
	// `Directory::owns_address` lower-cases the key (smtp/directory/mod.rs:412).
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "ALICE@EXAMPLE.ORG"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0][1]["created"]["s1"]["id"].is_string(),
		"owned mailFrom (case-insensitive) must be accepted: {body}"
	);
}
