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
	assert!(body["accounts"]["alice"].is_object(), "{body}");
	// Auth is required.
	let (status, _) = request(&app, "GET", "/jmap/session", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jmap_well_known_serves_session() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// RFC 8620 §2.2 autodiscovery path returns the Session resource.
	let (status, body) = request(&app, "GET", "/.well-known/jmap", Some(TOKEN)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["apiUrl"], "/jmap/api");
	assert!(
		body["capabilities"]["urn:ietf:params:jmap:core"].is_object(),
		"{body}"
	);
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

	let req = serde_json::json!({
		"using": [],
		"methodCalls": [["Widget/get", {}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(body["methodResponses"][0][1]["type"], "unknownMethod");
}

#[tokio::test]
async fn jmap_mailbox_set_creates_and_destroys() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/set", {
			"accountId": "alice",
			"create": { "c1": {"name": "Work", "parentId": null} },
		}, "m1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][0][1]["created"]["c1"]["id"], "Work");

	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "alice"}, "m2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	let names: Vec<_> = body["methodResponses"][0][1]["list"]
		.as_array()
		.expect("list")
		.iter()
		.map(|m| m["name"].as_str().unwrap_or("").to_string())
		.collect();
	assert!(names.contains(&"Work".to_string()), "{names:?}");

	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "destroy": ["Work"]}, "m3"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["destroyed"][0], "Work");
}

#[tokio::test]
async fn jmap_mailbox_query_lists_ids() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/query", {"accountId": "alice"}, "q1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let ids = body["methodResponses"][0][1]["ids"].to_string();
	assert!(ids.contains("INBOX") && ids.contains("Work"), "{ids}");
	assert_eq!(body["methodResponses"][0][1]["total"], 2);

	// Unknown account is reported, not a 500.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/query", {"accountId": "nobody"}, "q2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["type"], "accountNotFound");
}

#[tokio::test]
async fn jmap_mailbox_get_lists_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	std::fs::write(inbox.join(format!("{}.eml", uuid::Uuid::now_v7())), b"x").expect("write");

	let app = router(test_state(dir.path(), 0));
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
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
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

#[tokio::test]
async fn jmap_quota_get_reports_usage() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	std::fs::write(
		inbox.join(format!("{}.eml", uuid::Uuid::now_v7())),
		b"hello",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0).with_quota(1_000_000));
	let (_, session) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert!(
		session["capabilities"]["urn:ietf:params:jmap:quota"].is_object(),
		"{session}"
	);
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:quota"],
		"methodCalls": [["Quota/get", {"accountId": "alice"}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let quota = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(quota["limit"], 1_000_000);
	assert!(quota["used"].as_u64().expect("used") >= 5, "{quota}");
}

#[tokio::test]
async fn jmap_identity_get_lists_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, session) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert!(
		session["capabilities"]["urn:ietf:params:jmap:submission"].is_object(),
		"{session}"
	);
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["Identity/get", {"accountId": "alice"}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let identity = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(identity["email"], "alice@example.org");
	assert_eq!(identity["name"], "alice");
}

#[tokio::test]
async fn jmap_email_copy_duplicates_to_mailbox() {
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
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Saved"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;

	let req = serde_json::json!({
		"methodCalls": [["Email/copy", {
			"accountId": "alice", "fromAccountId": "alice",
			"create": { "k": {"emailId": id.to_string(), "mailboxIds": {"Saved": true}} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		body["methodResponses"][0][1]["created"]["k"]["id"].is_string(),
		"{body}"
	);
	let req = serde_json::json!({
		"methodCalls": [
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "INBOX"}}, "q1"],
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "Saved"}}, "q2"],
		],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["total"], 1);
	assert_eq!(body["methodResponses"][1][1]["total"], 1);
}

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
