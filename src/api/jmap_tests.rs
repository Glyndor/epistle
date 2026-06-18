//! JMAP endpoint tests (RFC 8620/8621).

use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};
use axum::http::StatusCode;

#[tokio::test]
async fn jmap_session_advertises_core_capability() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		body["capabilities"]["urn:ietf:params:jmap:core"].is_object(),
		"{body}"
	);
	assert_eq!(body["apiUrl"], "/jmap/api");
	// The configured account appears.
	assert!(body["accounts"]["alice"].is_object(), "{body}");
	// Auth is required.
	let (status, _) = request(&app, "GET", "/jmap/session", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jmap_core_echo_round_trips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:core"],
		"methodCalls": [["Core/echo", {"hello": "world"}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][0][0], "Core/echo");
	assert_eq!(body["methodResponses"][0][1]["hello"], "world");
	assert_eq!(body["methodResponses"][0][2], "c1");

	// An unknown method yields an error response, not a failure.
	let req = serde_json::json!({
		"using": [],
		"methodCalls": [["Widget/get", {}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(body["methodResponses"][0][1]["type"], "unknownMethod");
}

#[tokio::test]
async fn jmap_mailbox_get_lists_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Deliver a message so INBOX reports a count.
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	std::fs::write(inbox.join(format!("{}.eml", uuid::Uuid::now_v7())), b"x").expect("write");

	let app = router(test_state(dir.path(), 0));
	// The session advertises the mail capability.
	let (_, session) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert!(
		session["capabilities"]["urn:ietf:params:jmap:mail"].is_object(),
		"{session}"
	);

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/get", {"accountId": "alice", "ids": null}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let response = &body["methodResponses"][0];
	assert_eq!(response[0], "Mailbox/get");
	let inbox = &response[1]["list"][0];
	assert_eq!(inbox["name"], "INBOX");
	assert_eq!(inbox["role"], "inbox");
	assert_eq!(inbox["totalEmails"], 1);

	// An unknown account is reported, not a 500.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "nobody"}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(body["methodResponses"][0][1]["type"], "accountNotFound");
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
	// Gone from the mailbox: a follow-up Email/query is empty.
	let req = serde_json::json!({
		"methodCalls": [["Email/query", {"accountId": "alice"}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["total"], 0);
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
	let req = serde_json::json!({
		"methodCalls": [["Email/get", {"accountId": "alice", "ids": ["not-a-uuid"]}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["notFound"][0], "not-a-uuid");
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
