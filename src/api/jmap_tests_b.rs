//! JMAP endpoint tests (RFC 8620/8621).

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use axum::http::StatusCode;

#[tokio::test]
async fn jmap_email_set_creates_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"create": { "draft": {
				"mailboxIds": {"INBOX": true},
				"keywords": {"$draft": true},
				"from": [{"email": "alice@example.org"}],
				"to": [{"email": "bob@elsewhere.example"}],
				"subject": "Hello",
				"bodyValues": {"0": {"value": "the body"}},
			} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let id = body["methodResponses"][0][1]["created"]["draft"]["id"]
		.as_str()
		.expect("created id")
		.to_string();
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": [id]}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	let email = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(email["subject"], "Hello");
	assert_eq!(email["bodyValues"]["0"]["value"], "the body");
}

#[tokio::test]
async fn jmap_email_set_destroys_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"Subject: x\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/set", {"accountId": "alice", "destroy": [id.to_string()]}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		body["methodResponses"][0][1]["destroyed"][0],
		id.to_string()
	);
	let req = serde_json::json!({
		"methodCalls": [["Email/query", {"accountId": "alice"}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["total"], 0);
}

#[tokio::test]
async fn jmap_email_set_moves_between_mailboxes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"Subject: x\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));
	// Create the target folder.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c1": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;

	// Move the email to Work.
	let req = serde_json::json!({
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"update": { id.to_string(): {"mailboxIds": {"Work": true}} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(body["methodResponses"][0][1]["updated"][id.to_string()].is_null());
	// INBOX is now empty; Work has the message.
	let req = serde_json::json!({
		"methodCalls": [
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "INBOX"}}, "q1"],
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "Work"}}, "q2"],
		],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["total"], 0);
	assert_eq!(body["methodResponses"][1][1]["total"], 1);
}

#[tokio::test]
async fn jmap_email_set_updates_keywords() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"Subject: x\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"update": { id.to_string(): {"keywords": {"$seen": true}} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(body["methodResponses"][0][1]["updated"][id.to_string()].is_null());

	// Email/get now shows the $seen keyword.
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": [id.to_string()]}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["list"][0]["keywords"]["$seen"],
		true
	);
}

#[tokio::test]
async fn jmap_email_get_parses_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: Alice <a@example.org>\r\nTo: b@example.net\r\nSubject: Hi there\r\n\r\nthe body\r\n",
	)
	.expect("write");

	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": [id.to_string()]}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let email = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(email["subject"], "Hi there");
	assert_eq!(email["from"][0]["email"], "Alice <a@example.org>");
	assert_eq!(email["preview"], "the body");
	// bodyValues exposes the decoded text body (RFC 8621 §4.1.4).
	assert_eq!(email["bodyValues"]["0"]["value"], "the body\r\n");
	assert_eq!(email["textBody"][0]["type"], "text/plain");
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": ["not-a-uuid"]}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["notFound"][0], "not-a-uuid");
}

#[tokio::test]
async fn jmap_thread_get_returns_singleton_thread() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"Subject: x\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Thread/get", {"accountId": "alice", "ids": [id.to_string(), "missing"]}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let thread = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(thread["id"], id.to_string());
	assert_eq!(thread["emailIds"][0], id.to_string());
	assert_eq!(body["methodResponses"][0][1]["notFound"][0], "missing");
}

#[tokio::test]
async fn jmap_email_query_returns_ids() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	for _ in 0..3 {
		let id = uuid::Uuid::now_v7();
		std::fs::write(inbox.join(format!("{id}.eml")), b"x").expect("write");
	}
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/query", {"accountId": "alice", "filter": {"inMailbox": "INBOX"}}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let response = &body["methodResponses"][0][1];
	assert_eq!(response["total"], 3);
	assert_eq!(response["ids"].as_array().expect("ids").len(), 3);
}

#[tokio::test]
async fn jmap_methods_reject_missing_account_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// Every account-scoped method reports invalidArguments without accountId.
	for method in [
		"Mailbox/get",
		"Mailbox/set",
		"Mailbox/query",
		"Email/query",
		"Email/get",
		"Email/set",
		"Email/copy",
		"Thread/get",
		"Identity/get",
		"Quota/get",
		"EmailSubmission/set",
	] {
		let req = serde_json::json!({ "methodCalls": [[method, {}, "c1"]] });
		let (status, body) =
			request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(body["methodResponses"][0][0], "error", "{method}: {body}");
		assert_eq!(
			body["methodResponses"][0][1]["type"], "invalidArguments",
			"{method}: {body}"
		);
	}
}

#[tokio::test]
async fn jmap_email_set_reports_unknown_ids() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let ghost = uuid::Uuid::now_v7().to_string();

	// Destroying and updating an absent email report notFound, not a crash.
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"destroy": [ghost],
			"update": { "missing-id": {"keywords": {"$seen": true}} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let result = &body["methodResponses"][0][1];
	assert_eq!(result["notDestroyed"][&ghost]["type"], "notFound", "{body}");
	assert_eq!(
		result["notUpdated"]["missing-id"]["type"], "notFound",
		"{body}"
	);

	// A present-but-unknown account is reported as accountNotFound.
	for method in ["Email/set", "Email/copy"] {
		let req = serde_json::json!({
			"methodCalls": [[method, {"accountId": "ghost-account"}, "c2"]],
		});
		let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
		assert_eq!(
			body["methodResponses"][0][1]["type"], "accountNotFound",
			"{method}: {body}"
		);
	}
}

#[tokio::test]
async fn jmap_changes_methods_report_cannot_calculate() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	for method in ["Mailbox/changes", "Email/changes", "Thread/changes"] {
		let req = serde_json::json!({ "methodCalls": [[method, {"accountId": "alice"}, "c1"]] });
		let (status, body) =
			request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(
			body["methodResponses"][0][1]["type"], "cannotCalculateChanges",
			"{method}: {body}"
		);
	}
	// Without an account it is invalidArguments.
	let req = serde_json::json!({ "methodCalls": [["Email/changes", {}, "c2"]] });
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(
		body["methodResponses"][0][1]["type"], "invalidArguments",
		"{body}"
	);
}

/// JMAP `Email/set` create builds RFC 5322 with the user's `from`, `to` and
/// `subject` interpolated raw. Without sanitization, a CRLF in any of those
/// would inject forged headers (Bcc, X-*, …) into the stored message. This
/// test exercises the rejection half: a CRLF in `subject` cannot survive
/// into the produced bytes; the matching acceptance case is the suite of
/// `Email/set` create tests above (they use a benign subject).
#[tokio::test]
async fn jmap_email_set_sanitises_header_injection_in_subject() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// Subject contains a CRLF that, if interpolated raw, would terminate the
	// header line and start a new `Bcc:` header.
	let req = serde_json::json!({
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"create": { "d1": {
				"mailboxIds": {"INBOX": true},
				"from": [{"email": "alice@example.org"}],
				"to": [{"email": "alice@example.org"}],
				"subject": "hi\r\nBcc: attacker@evil.example",
			} },
		}, "c1"]],
	});
	let (status, _body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	// Pull the stored message back. Append goes to `INBOX/cur` after
	// delivery (delivery moves it from `new`).
	let find_message = |dir: &std::path::Path| -> Option<Vec<u8>> {
		let entries = std::fs::read_dir(dir).ok()?;
		for entry in entries.flatten() {
			if let Ok(bytes) = std::fs::read(entry.path()) {
				return Some(bytes);
			}
		}
		None
	};
	let raw = find_message(&dir.path().join("accounts").join("alice").join("cur"))
		.or_else(|| find_message(&dir.path().join("accounts").join("alice").join("new")))
		.expect("stored message");
	let text = String::from_utf8_lossy(&raw);
	// The sanitiser collapses CRLF to spaces, so the substring `Bcc:` may
	// still appear inside the `Subject:` value (as opaque text on the same
	// line). The structural property that defeats the injection is that
	// no line in the header block starts with `Bcc:`, which is what an
	// un-sanitised CRLF would produce.
	for line in text.lines() {
		assert!(
			!line.to_ascii_lowercase().starts_with("bcc:"),
			"forged Bcc: must not appear as its own header: {line:?}"
		);
	}
	// And the original `Subject:` line is on a single line (no embedded CRLF).
	let subject_line = text
		.lines()
		.find(|line| line.to_ascii_lowercase().starts_with("subject:"))
		.expect("subject header");
	assert!(
		!subject_line.contains('\r') && !subject_line.contains('\n'),
		"Subject: line must not contain CRLF: {subject_line:?}"
	);
}
