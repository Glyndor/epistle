//! JMAP `/queryChanges` tests (RFC 8620 §5.6).
//!
//! Split out of `jmap_tests_changes` so the per-file line cap
//! holds without dropping a test.

use super::jmap_tests_changes_helpers::*;
use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use serde_json::{Value, json};

#[tokio::test]
async fn jmap_mailbox_query_changes_is_calculable_for_unfiltered_query() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let since = fetch_mailbox_state(&app, "alice").await;
	let req = json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/queryChanges", {"accountId": "alice", "sinceQueryState": since}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let resp = &body["methodResponses"][0][1];
	assert_eq!(
		body["methodResponses"][0][0], "Mailbox/queryChanges",
		"unfiltered mailbox query must be calculable: {resp}"
	);
	let added: Vec<Value> = resp["added"].as_array().expect("added array").clone();
	assert!(
		added
			.iter()
			.any(|v| v.get("id").and_then(Value::as_str) == Some("Work")),
		"added must include Work: {resp}"
	);
}

/// Sanity: the `state` returned by `Email/get` matches the `queryState`
/// returned by `Email/query` for the same account. They share the
/// underlying counter, so a sync client can use them interchangeably.
#[tokio::test]
async fn jmap_email_state_and_query_state_match() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let _id = append_to_inbox(dir.path(), "alice");
	let email_state = fetch_email_state(&app, "alice").await;
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/query", {"accountId": "alice"}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let query_state = body["methodResponses"][0][1]["queryState"]
		.as_str()
		.expect("queryState is a string")
		.to_string();
	assert_eq!(
		email_state, query_state,
		"Email state and Email/query queryState share the same counter"
	);
}

async fn call(app: &axum::Router, method: &str, args: Value) -> Value {
	let req = json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [[method, args, "c1"]],
	});
	let (_, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	body["methodResponses"][0].clone()
}

/// New deliveries are added at their place in the newest-first results and
/// an expunged message is removed; nothing else is reported.
#[tokio::test]
async fn email_query_changes_reports_exact_additions_and_removals() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let first = append_to_inbox(dir.path(), "alice");
	let since = fetch_email_state(&app, "alice").await;
	let second = append_to_inbox(dir.path(), "alice");
	let third = append_to_inbox(dir.path(), "alice");
	store_deleted(dir.path(), "alice", "INBOX");
	expunge_first(dir.path(), "alice", "INBOX");
	let args = json!({
		"accountId": "alice",
		"sinceQueryState": since,
		"filter": {"inMailbox": "INBOX"},
		"sort": [{"property": "receivedAt", "isAscending": false}],
		"calculateTotal": true,
	});
	let resp = call(&app, "Email/queryChanges", args.clone()).await;
	assert_eq!(resp[0], "Email/queryChanges", "{resp}");
	assert_eq!(resp[1]["oldQueryState"], json!(since));
	assert_eq!(resp[1]["removed"], json!([first]), "{resp}");
	assert_eq!(
		resp[1]["added"],
		json!([{"id": third, "index": 0}, {"id": second, "index": 1}]),
		"{resp}"
	);
	assert_eq!(resp[1]["total"], 2);
	let query = call(&app, "Email/query", json!({"accountId": "alice"})).await;
	assert_eq!(resp[1]["newQueryState"], query[1]["queryState"]);
	let mut capped = args;
	capped["maxChanges"] = json!(2);
	let resp = call(&app, "Email/queryChanges", capped).await;
	assert_eq!(resp[0], "error");
	assert_eq!(resp[1]["type"], "tooManyChanges", "{resp}");
}

/// `Email/query` only promises `canCalculateChanges` for the shapes
/// `Email/queryChanges` can replay.
#[tokio::test]
async fn email_query_can_calculate_changes_only_for_replayable_queries() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	for (args, expected) in [
		(json!({"accountId": "alice"}), true),
		(
			json!({"accountId": "alice", "filter": {"inMailbox": "INBOX"}}),
			true,
		),
		(
			json!({"accountId": "alice", "filter": {"text": "x"}}),
			false,
		),
		(
			json!({"accountId": "alice", "sort": [{"property": "receivedAt"}]}),
			false,
		),
	] {
		let resp = call(&app, "Email/query", args.clone()).await;
		assert_eq!(resp[1]["canCalculateChanges"], expected, "{args}");
	}
}

/// A created mailbox is added at its place among INBOX and the sorted
/// folders; a mailbox whose counts alone changed is not reported.
#[tokio::test]
async fn mailbox_query_changes_reports_the_new_mailbox_at_its_index() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	crate::imap::mailbox::create(dir.path(), "alice", "Zeta").expect("create");
	let since = fetch_mailbox_state(&app, "alice").await;
	crate::imap::mailbox::create(dir.path(), "alice", "Alpha").expect("create");
	append_to_inbox(dir.path(), "alice");
	let resp = call(
		&app,
		"Mailbox/queryChanges",
		json!({"accountId": "alice", "sinceQueryState": since}),
	)
	.await;
	assert_eq!(resp[1]["removed"], json!([]), "{resp}");
	assert_eq!(
		resp[1]["added"],
		json!([{"id": "Alpha", "index": 1}]),
		"{resp}"
	);
	assert_eq!(
		resp[1]["newQueryState"],
		json!(fetch_mailbox_state(&app, "alice").await)
	);
}

/// A keyword change does not change a Thread, so `Thread/changes` reports
/// only created and destroyed threads.
#[tokio::test]
async fn thread_changes_ignores_keyword_updates() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	append_to_inbox(dir.path(), "alice");
	let req = json!({
		"methodCalls": [["Thread/get", {"accountId": "alice", "ids": []}, "t"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let since = body["methodResponses"][0][1]["state"].clone();
	store_seen(dir.path(), "alice", "INBOX");
	let fresh = append_to_inbox(dir.path(), "alice");
	let resp = call(
		&app,
		"Thread/changes",
		json!({"accountId": "alice", "sinceState": since}),
	)
	.await;
	assert_eq!(resp[1]["created"], json!([fresh]), "{resp}");
	assert_eq!(resp[1]["updated"], json!([]), "{resp}");
}
