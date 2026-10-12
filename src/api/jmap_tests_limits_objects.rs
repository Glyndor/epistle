//! `maxObjectsInGet` and `maxObjectsInSet` (RFC 8620 §2) are what the server
//! applies: a `/get` naming more ids, or a `/set` carrying more creates,
//! updates and destroys together, is answered `requestTooLarge` (§5.1, §5.3)
//! and nothing in it runs.

use super::jmap::{MAX_OBJECTS_IN_GET, MAX_OBJECTS_IN_SET};
use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};
use axum::Router;
use axum::http::StatusCode;
use serde_json::{Map, Value, json};

const CORE: &str = "urn:ietf:params:jmap:core";

/// Send one method call and return its response triple.
async fn call(app: &Router, method: &str, args: Value) -> Value {
	let body = json!({ "using": [CORE], "methodCalls": [[method, args, "c1"]] });
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(body)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0].clone()
}

fn ids(count: usize) -> Vec<String> {
	(0..count).map(|i| format!("missing-{i}")).collect()
}

fn is_too_large(response: &Value) -> bool {
	response[0] == "error" && response[1]["type"] == "requestTooLarge" && response[2] == "c1"
}

#[tokio::test]
async fn session_advertises_the_enforced_object_limits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, body) = request(&app, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	let core = &body["capabilities"][CORE];
	assert_eq!(core["maxObjectsInGet"], MAX_OBJECTS_IN_GET);
	assert_eq!(core["maxObjectsInSet"], MAX_OBJECTS_IN_SET);
}

#[tokio::test]
async fn a_get_over_max_objects_in_get_is_request_too_large() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	for method in [
		"Email/get",
		"Thread/get",
		"Mailbox/get",
		"Identity/get",
		"Quota/get",
		"PushSubscription/get",
	] {
		let at_limit = call(
			&app,
			method,
			json!({ "accountId": "alice", "ids": ids(MAX_OBJECTS_IN_GET) }),
		)
		.await;
		assert_eq!(at_limit[0], method, "{method} at the limit runs");

		let over = call(
			&app,
			method,
			json!({ "accountId": "alice", "ids": ids(MAX_OBJECTS_IN_GET + 1) }),
		)
		.await;
		assert!(is_too_large(&over), "{method} over the limit: {}", over[0]);
	}
}

#[tokio::test]
async fn a_set_over_max_objects_in_set_is_request_too_large_and_runs_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	// Creates and destroys count together: one over the limit in total.
	let create: Map<String, Value> = (0..MAX_OBJECTS_IN_SET / 2)
		.map(|i| (format!("k{i}"), json!({ "name": format!("box-{i}") })))
		.collect();
	let destroy = ids(MAX_OBJECTS_IN_SET - create.len() + 1);
	let over = call(
		&app,
		"Mailbox/set",
		json!({ "accountId": "alice", "create": create, "destroy": destroy }),
	)
	.await;
	assert!(
		is_too_large(&over),
		"Mailbox/set over the limit: {}",
		over[0]
	);
	let mailboxes = crate::imap::mailbox::list(dir.path(), "alice");
	assert!(
		!mailboxes.iter().any(|name| name.starts_with("box-")),
		"a refused /set creates nothing: {} mailboxes",
		mailboxes.len()
	);

	let at_limit = call(
		&app,
		"Mailbox/set",
		json!({ "accountId": "alice", "destroy": ids(MAX_OBJECTS_IN_SET) }),
	)
	.await;
	assert_eq!(at_limit[0], "Mailbox/set");

	for method in ["Email/set", "EmailSubmission/set", "PushSubscription/set"] {
		let over = call(
			&app,
			method,
			json!({ "accountId": "alice", "destroy": ids(MAX_OBJECTS_IN_SET + 1) }),
		)
		.await;
		assert!(is_too_large(&over), "{method} over the limit: {}", over[0]);
	}
}

/// `ids: null` asks for every mailbox, which RFC 8620 §5.1 allows only while
/// their number stays within `maxObjectsInGet`.
#[tokio::test]
async fn mailbox_get_of_all_is_request_too_large_past_max_objects_in_get() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let mut index = 0;
	while crate::imap::mailbox::list(dir.path(), "alice").len() < MAX_OBJECTS_IN_GET + 1 {
		crate::imap::mailbox::create(dir.path(), "alice", &format!("m{index}")).expect("create");
		index += 1;
	}

	let over = call(
		&app,
		"Mailbox/get",
		json!({ "accountId": "alice", "ids": null }),
	)
	.await;
	assert!(is_too_large(&over), "Mailbox/get of all: {}", over[0]);

	crate::imap::mailbox::delete(dir.path(), "alice", "m0").expect("delete");
	let at_limit = call(
		&app,
		"Mailbox/get",
		json!({ "accountId": "alice", "ids": null }),
	)
	.await;
	assert_eq!(at_limit[0], "Mailbox/get");
	assert_eq!(
		at_limit[1]["list"].as_array().map(Vec::len),
		Some(MAX_OBJECTS_IN_GET)
	);
}
