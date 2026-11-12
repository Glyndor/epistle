//! JMAP `Email/copy`, mailbox and back-reference tests.

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use axum::http::StatusCode;

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
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;

	let req = serde_json::json!({
		"methodCalls": [["Email/copy", {
			"accountId": "alice", "fromAccountId": "alice",
			"create": { "k": {"id": id.to_string(), "mailboxIds": {"Saved": true}} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
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
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["total"], 1);
	assert_eq!(body["methodResponses"][1][1]["total"], 1);
}

#[tokio::test]
async fn jmap_mailbox_set_update_create_invalid_and_destroy_unknown() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));

	// Create a folder to rename.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;

	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {
			"accountId": "alice",
			"create": { "bad": {} },
			"update": { "Work": {"name": "Projects"}, "Ghost": {"name": "X"} },
			"destroy": ["Nonexistent"],
		}, "m2"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let r = &body["methodResponses"][0][1];
	// A create without a name is rejected.
	assert_eq!(
		r["notCreated"]["bad"]["type"], "invalidProperties",
		"{body}"
	);
	// Renaming the real folder succeeds; the unknown one is rejected.
	assert!(r["updated"].get("Work").is_some(), "{body}");
	assert_eq!(
		r["notUpdated"]["Ghost"]["type"], "invalidProperties",
		"{body}"
	);
	// Destroying a missing mailbox reports notFound.
	assert_eq!(
		r["notDestroyed"]["Nonexistent"]["type"], "notFound",
		"{body}"
	);
}

#[tokio::test]
async fn jmap_mailbox_get_filters_by_ids() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;

	// Request only INBOX by id: Work is filtered out.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "alice", "ids": ["INBOX"]}, "m2"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let names: Vec<String> = body["methodResponses"][0][1]["list"]
		.as_array()
		.expect("list")
		.iter()
		.map(|m| m["name"].as_str().unwrap_or("").to_string())
		.collect();
	assert_eq!(names, vec!["INBOX".to_string()], "{body}");
}

#[tokio::test]
async fn jmap_query_changes_reports_cannot_calculate() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/queryChanges", {"accountId": "alice", "sinceQueryState": "0"}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(
		body["methodResponses"][0][1]["type"],
		"cannotCalculateChanges"
	);
}

#[tokio::test]
async fn jmap_result_back_reference_chains_calls() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// Mailbox/query then Mailbox/get the resulting ids via a back-reference.
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [
			["Mailbox/query", {"accountId": "alice"}, "q1"],
			["Mailbox/get", {
				"accountId": "alice",
				"#ids": {"resultOf": "q1", "name": "Mailbox/query", "path": "/ids"}
			}, "g1"]
		],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][1][0], "Mailbox/get");
	// The INBOX resolved from the query's ids is present in the get result.
	let list = body["methodResponses"][1][1]["list"].to_string();
	assert!(list.contains("INBOX"), "{list}");
}

#[allow(unused_imports)]
use super::super::quota;
