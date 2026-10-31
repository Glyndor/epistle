//! Result back-references (RFC 8620 §3.7) are held to the Session's object
//! limits one reference at a time: a reference may resolve to as many ids as
//! a `/get` or `/set` may name, and what earlier calls returned does not
//! count against later ones.

use super::super::jmap::MAX_OBJECTS_IN_GET;
use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use axum::Router;
use axum::http::StatusCode;
use serde_json::{Map, Value, json};

const CORE: &str = "urn:ietf:params:jmap:core";
const MAIL: &str = "urn:ietf:params:jmap:mail";

/// Send `calls` in one request and return the method responses.
async fn send(app: &Router, calls: Value) -> Vec<Value> {
	let body = json!({ "using": [CORE, MAIL], "methodCalls": calls });
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(body)).await;
	assert_eq!(status, StatusCode::OK, "{}", body["type"]);
	body["methodResponses"]
		.as_array()
		.cloned()
		.expect("responses")
}

fn ids(count: usize) -> Vec<String> {
	(0..count).map(|i| format!("missing-{i}")).collect()
}

fn reference(result_of: &str, name: &str, path: &str) -> Value {
	json!({ "resultOf": result_of, "name": name, "path": path })
}

/// The method name of a response and, for an error, its type.
fn outcome(response: &Value) -> String {
	match response[0].as_str() {
		Some("error") => format!("error {}", response[1]["type"]),
		Some(name) => name.to_string(),
		None => "missing".to_string(),
	}
}

#[tokio::test]
async fn email_get_resolves_the_ids_of_a_450_message_query() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice/new")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let create: Map<String, Value> = (0..450)
		.map(|i| {
			let draft = json!({
				"mailboxIds": { "INBOX": true },
				"from": [{ "email": "alice@example.org" }],
				"subject": format!("m{i}"),
			});
			(format!("d{i}"), draft)
		})
		.collect();
	let created = send(
		&app,
		json!([["Email/set", { "accountId": "alice", "create": create }, "s"]]),
	)
	.await;
	assert_eq!(
		created[0][1]["created"].as_object().map(Map::len),
		Some(450)
	);

	let responses = send(
		&app,
		json!([
			["Email/query", { "accountId": "alice", "filter": { "inMailbox": "INBOX" } }, "q"],
			["Email/get", {
				"accountId": "alice",
				"#ids": reference("q", "Email/query", "/ids"),
				"properties": ["id"],
			}, "g"],
		]),
	)
	.await;
	assert_eq!(responses[0][1]["ids"].as_array().map(Vec::len), Some(450));
	assert_eq!(outcome(&responses[1]), "Email/get");
	assert_eq!(responses[1][1]["list"].as_array().map(Vec::len), Some(450));
}

#[tokio::test]
async fn a_back_reference_is_capped_at_max_objects_in_get() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let too_large = "error \"requestTooLarge\"";
	// `Core/echo` has no object limit of its own: only the reference cap
	// stands between it and the oversize reference.
	for method in ["Email/get", "Core/echo"] {
		for (count, expected) in [
			(MAX_OBJECTS_IN_GET, method),
			(MAX_OBJECTS_IN_GET + 1, too_large),
		] {
			let responses = send(
				&app,
				json!([
					["Core/echo", { "ids": ids(count) }, "e"],
					[method, {
						"accountId": "alice",
						"#ids": reference("e", "Core/echo", "/ids"),
					}, "g"],
				]),
			)
			.await;
			assert_eq!(
				outcome(&responses[1]),
				expected,
				"{method} with {count} ids"
			);
		}
	}
}

/// References within the object cap still cannot together resolve to more
/// than a request may carry, so repeating one cannot amplify a request.
#[tokio::test]
async fn references_together_are_capped_at_max_size_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// 500 ids of 1000 octets: about 500 kB per reference.
	let wide: Vec<String> = (0..MAX_OBJECTS_IN_GET)
		.map(|i| format!("{i:01000}"))
		.collect();
	let call = |copies: usize| {
		let refs: Map<String, Value> = (0..copies)
			.map(|k| (format!("#k{k}"), reference("e", "Core/echo", "/ids")))
			.collect();
		json!([["Core/echo", { "ids": wide }, "e"], ["Core/echo", refs, "r"]])
	};
	let responses = send(&app, call(2)).await;
	assert_eq!(outcome(&responses[1]), "Core/echo");
	let responses = send(&app, call(25)).await;
	assert_eq!(outcome(&responses[1]), "error \"requestTooLarge\"");
}

/// A large result does not use up the request: a later call that refers to
/// nothing still runs.
#[tokio::test]
async fn a_large_result_does_not_refuse_the_calls_after_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let responses = send(
		&app,
		json!([
			["Core/echo", { "ids": ids(250) }, "a"],
			["Core/echo", {}, "b"],
		]),
	)
	.await;
	assert_eq!(outcome(&responses[1]), "Core/echo");
}
