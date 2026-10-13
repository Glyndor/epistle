//! JMAP reads need the `read` scope, the way writes need `write` and
//! `EmailSubmission/set` needs `send`. Scopes are independent: a key issued
//! only to send, or only to write, does not also read the mailbox.

use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};
use axum::http::StatusCode;
use serde_json::{Value, json};

const READER: &str = "reader-secret";
const SENDER: &str = "sender-secret";
const WRITER: &str = "writer-secret";

fn app(dir: &std::path::Path) -> axum::Router {
	std::fs::create_dir_all(dir.join("accounts").join("alice")).expect("mkdir");
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	for (label, secret, scope) in [
		("reader", READER, "read"),
		("sender", SENDER, "send"),
		("writer", WRITER, "write"),
	] {
		key_store
			.add(crate::api::api_keys::ApiKey {
				label: label.to_string(),
				hash: crate::api::api_keys::sha256_hash(secret),
				expires_at: None,
				ip_cidr: None,
				scopes: vec![scope.to_string()],
				domains: Vec::new(),
				account: Some("alice".to_string()),
			})
			.expect("add key");
	}
	drop(key_store);
	router(test_state(dir, 0))
}

/// The responses to `calls`, made with `token`.
async fn call(app: &axum::Router, token: &str, calls: Value) -> Vec<Value> {
	let envelope = json!({
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": calls,
	});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(token), Some(envelope)).await;
	assert_eq!(status, StatusCode::OK, "the envelope itself is accepted");
	body["methodResponses"]
		.as_array()
		.expect("methodResponses")
		.clone()
}

/// Every JMAP read method with arguments it answers successfully for alice:
/// the `/changes` and `/queryChanges` calls start from the current state.
async fn read_calls(app: &axum::Router) -> Vec<(&'static str, Value)> {
	let states = call(
		app,
		TOKEN.as_str(),
		json!([
			["Mailbox/get", { "accountId": "alice" }, "m"],
			["Email/get", { "accountId": "alice", "ids": [] }, "e"],
			["Thread/get", { "accountId": "alice", "ids": [] }, "t"],
			["Mailbox/query", { "accountId": "alice" }, "mq"],
			["Email/query", { "accountId": "alice" }, "eq"],
		]),
	)
	.await;
	let state = |i: usize, field: &str| states[i][1][field].clone();
	vec![
		("Mailbox/get", json!({ "accountId": "alice" })),
		("Mailbox/query", json!({ "accountId": "alice" })),
		(
			"Mailbox/changes",
			json!({ "accountId": "alice", "sinceState": state(0, "state") }),
		),
		(
			"Mailbox/queryChanges",
			json!({ "accountId": "alice", "sinceQueryState": state(3, "queryState") }),
		),
		("Email/get", json!({ "accountId": "alice", "ids": [] })),
		("Email/query", json!({ "accountId": "alice" })),
		(
			"Email/changes",
			json!({ "accountId": "alice", "sinceState": state(1, "state") }),
		),
		(
			"Email/queryChanges",
			json!({ "accountId": "alice", "sinceQueryState": state(4, "queryState") }),
		),
		("Thread/get", json!({ "accountId": "alice", "ids": [] })),
		(
			"Thread/changes",
			json!({ "accountId": "alice", "sinceState": state(2, "state") }),
		),
		("Identity/get", json!({ "accountId": "alice" })),
		("Quota/get", json!({ "accountId": "alice" })),
		("PushSubscription/get", json!({})),
	]
}

fn mailbox_create() -> Value {
	json!([[
		"Mailbox/set",
		{ "accountId": "alice", "create": { "n": { "name": "Work" } } },
		"w"
	]])
}

#[tokio::test]
async fn a_read_only_key_reads_every_type_and_cannot_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	for (method, args) in read_calls(&app).await {
		let responses = call(&app, READER, json!([[method, args, "r"]])).await;
		assert_eq!(
			responses[0][0], method,
			"a read key must be answered by {method}: {}",
			responses[0][1]
		);
	}
	let responses = call(&app, READER, mailbox_create()).await;
	assert_eq!(
		responses[0],
		json!(["error", { "type": "forbidden" }, "w"]),
		"a read key must not create a mailbox"
	);
}

#[tokio::test]
async fn send_only_and_write_only_keys_cannot_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let reads = read_calls(&app).await;
	for key in [SENDER, WRITER] {
		let label = if key == SENDER { "send" } else { "write" };
		for (method, args) in &reads {
			let responses = call(&app, key, json!([[method, args, "r"]])).await;
			assert_eq!(
				responses[0],
				json!(["error", { "type": "forbidden" }, "r"]),
				"a {label}-only key must not be answered by {method}"
			);
		}
		for path in ["/jmap/session", "/.well-known/jmap"] {
			let (status, _) = request(&app, "GET", path, Some(key)).await;
			assert_eq!(
				status,
				StatusCode::UNAUTHORIZED,
				"a {label}-only key must not list accounts at {path}"
			);
		}
	}
}

#[tokio::test]
async fn a_write_only_key_still_writes_and_cannot_download() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let responses = call(&app, WRITER, mailbox_create()).await;
	assert_eq!(responses[0][0], "Mailbox/set", "{}", responses[0][1]);
	assert!(
		responses[0][1]["created"]["n"].is_object(),
		"a write key creates the mailbox: {}",
		responses[0][1]
	);
	let (status, upload) = request_with_body(
		&app,
		"POST",
		"/jmap/upload/alice",
		Some(WRITER),
		Some(json!({ "blob": true })),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "a write key uploads");
	let blob = upload["blobId"].as_str().expect("blobId");
	let download = format!("/jmap/download/alice/{blob}/b.json");
	let (status, _) = request(&app, "GET", &download, Some(WRITER)).await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"a write-only key must not download"
	);
	let (status, _) = request(&app, "GET", &download, Some(READER)).await;
	assert_eq!(status, StatusCode::OK, "a read key downloads the blob");
}
