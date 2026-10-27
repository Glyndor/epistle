//! Cross-account object access, batch and reference amplification, and upload caps.

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::harness::{ADMIN, ALICE, Harness, UPLOAD_LIMIT, api_request, call, repeated_body};

const CORE: &str = "urn:ietf:params:jmap:core";

async fn admin_calls(h: &Harness, calls: Value) -> Value {
	let reply = call(
		&h.api,
		api_request(
			"POST",
			"/jmap/api",
			ADMIN,
			Body::from(json!({"methodCalls": calls}).to_string()),
		),
	)
	.await;
	assert_eq!(reply.status, StatusCode::OK);
	reply.json()
}

fn method_error(body: &Value, index: usize, kind: &str, id: &str) {
	assert_eq!(
		body["methodResponses"][index],
		json!(["error", {"type": kind}, id])
	);
}

#[tokio::test]
async fn foreign_email_id_is_not_found_in_own_account() {
	let h = Harness::new();
	let id = uuid::Uuid::now_v7().to_string();
	let raw = b"From: bob@example.test\r\nSubject: BOB-PRIVATE-SENTINEL\r\n\r\nPrivate body\r\n";
	std::fs::write(h.root().join(format!("accounts/bob/new/{id}.eml")), raw).expect("bob mail");
	// A positive control proves this is a real readable object, not a guessed id.
	let control = admin_calls(&h, json!([["Email/get", {"accountId": "bob", "ids": [id], "properties": ["id", "subject"]}, "owner"]])).await;
	assert_eq!(control["methodResponses"][0][1]["list"][0]["id"], id);
	let reply = h.jmap(json!([["Email/get", {"accountId": "alice", "ids": [id], "properties": ["id", "subject"]}, "attack"]])).await;
	assert_eq!(reply.status, StatusCode::OK);
	let body = reply.json();
	assert_eq!(body["methodResponses"][0][0], "Email/get");
	assert_eq!(body["methodResponses"][0][1]["list"], json!([]));
	assert_eq!(body["methodResponses"][0][1]["notFound"], json!([id]));
	assert!(!String::from_utf8_lossy(&reply.body).contains("BOB-PRIVATE-SENTINEL"));
	h.healthy_api().await;
}

#[tokio::test]
async fn foreign_account_and_nonexistent_account_have_same_method_error() {
	let h = Harness::new();
	for account in ["bob", "does-not-exist"] {
		let reply = h
			.jmap(json!([
				["Email/get", {"accountId": account, "ids": [uuid::Uuid::now_v7()]}, "email"],
				["Mailbox/get", {"accountId": account, "ids": ["INBOX"]}, "mailbox"],
			]))
			.await;
		assert_eq!(reply.status, StatusCode::OK);
		method_error(&reply.json(), 0, "accountNotFound", "email");
		method_error(&reply.json(), 1, "accountNotFound", "mailbox");
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn foreign_blob_id_cannot_be_downloaded_under_either_account_name() {
	let h = Harness::new();
	let uploaded = call(
		&h.api,
		api_request(
			"POST",
			"/jmap/upload/bob",
			ADMIN,
			Body::from("BOB-PRIVATE-BLOB"),
		),
	)
	.await;
	assert_eq!(uploaded.status, StatusCode::OK);
	let id = uploaded.json()["blobId"]
		.as_str()
		.expect("blob id")
		.to_string();
	let control = call(
		&h.api,
		api_request(
			"GET",
			&format!("/jmap/download/bob/{id}/f"),
			ADMIN,
			Body::empty(),
		),
	)
	.await;
	assert_eq!(control.status, StatusCode::OK);
	assert_eq!(control.body, b"BOB-PRIVATE-BLOB");
	for account in ["bob", "alice"] {
		let reply = call(
			&h.api,
			api_request(
				"GET",
				&format!("/jmap/download/{account}/{id}/f"),
				ALICE,
				Body::empty(),
			),
		)
		.await;
		assert_eq!(reply.status, StatusCode::NOT_FOUND);
		assert_eq!(reply.json()["type"], "urn:ietf:params:jmap:error:notFound");
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn foreign_account_upload_is_refused() {
	let h = Harness::new();
	let reply = call(
		&h.api,
		api_request("POST", "/jmap/upload/bob", ALICE, Body::from("injected")),
	)
	.await;
	assert_eq!(reply.status, StatusCode::NOT_FOUND);
	assert_eq!(reply.json()["type"], "urn:ietf:params:jmap:error:notFound");
	assert!(!h.root().join("blobs/accounts/bob").exists());
	h.healthy_api().await;
}

async fn advertised(h: &Harness, name: &str) -> usize {
	let reply = call(
		&h.api,
		api_request("GET", "/jmap/session", ALICE, Body::empty()),
	)
	.await;
	assert_eq!(reply.status, StatusCode::OK);
	reply.json()["capabilities"][CORE][name]
		.as_u64()
		.expect("advertised limit") as usize
}

#[tokio::test]
async fn thousands_of_calls_are_refused_before_mutation() {
	let h = Harness::new();
	let mut calls = vec![
		json!(["Mailbox/set", {"accountId": "alice", "create": {"x": {"name": "MustNotExist"}}}, "mutator"]),
	];
	calls.extend((1..4000).map(|n| json!(["Core/echo", {}, format!("c{n}")])));
	let reply = h.jmap(Value::Array(calls)).await;
	assert_eq!(reply.status, StatusCode::BAD_REQUEST);
	assert_eq!(reply.json()["limit"], "maxCallsInRequest");
	assert_eq!(reply.json()["type"], "urn:ietf:params:jmap:error:limit");
	assert!(reply.json().get("methodResponses").is_none());
	let check = h
		.jmap(json!([["Mailbox/get", {"accountId": "alice", "ids": ["MustNotExist"]}, "check"]]))
		.await;
	assert_eq!(check.status, StatusCode::OK);
	assert_eq!(check.json()["methodResponses"][0][0], "Mailbox/get");
	assert_eq!(check.json()["methodResponses"][0][1]["list"], json!([]));
	h.healthy_api().await;
}

#[tokio::test]
async fn advertised_max_calls_boundary_is_enforced() {
	let h = Harness::new();
	let limit = advertised(&h, "maxCallsInRequest").await;
	assert_eq!(limit, 16, "expected production contract");
	for count in [limit, limit + 1] {
		let calls: Vec<_> = (0..count)
			.map(|n| json!(["Core/echo", {"n": n}, format!("c{n}")]))
			.collect();
		let reply = h.jmap(Value::Array(calls)).await;
		if count == limit {
			assert_eq!(reply.status, StatusCode::OK);
			assert_eq!(
				reply.json()["methodResponses"]
					.as_array()
					.expect("responses")
					.len(),
				limit
			);
		} else {
			assert_eq!(reply.status, StatusCode::BAD_REQUEST);
			assert_eq!(reply.json()["limit"], "maxCallsInRequest");
		}
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn advertised_max_objects_in_get_boundary_is_enforced() {
	let h = Harness::new();
	let limit = advertised(&h, "maxObjectsInGet").await;
	assert_eq!(limit, 500, "expected production contract");
	for count in [limit, limit + 1] {
		let ids: Vec<_> = (0..count).map(|n| format!("missing-{n}")).collect();
		let reply = h
			.jmap(json!([["Email/get", {"accountId": "alice", "ids": ids}, "get"]]))
			.await;
		assert_eq!(reply.status, StatusCode::OK);
		if count == limit {
			assert_eq!(reply.json()["methodResponses"][0][0], "Email/get");
			assert_eq!(
				reply.json()["methodResponses"][0][1]["notFound"],
				json!(ids)
			);
		} else {
			method_error(&reply.json(), 0, "requestTooLarge", "get");
		}
		h.healthy_api().await;
	}
}

fn reference(result: &str, path: &str) -> Value {
	json!({"resultOf": result, "name": "Core/echo", "path": path})
}

#[tokio::test]
async fn self_and_forward_circular_references_fail_without_recursion() {
	let h = Harness::new();
	let reply = h
		.jmap(json!([
			["Core/echo", {"#x": reference("self", "/x")}, "self"],
			["Core/echo", {"#x": reference("last", "/x")}, "first"],
			["Core/echo", {"#x": reference("first", "/x")}, "last"],
			["Core/echo", {"alive": true}, "after"],
		]))
		.await;
	assert_eq!(reply.status, StatusCode::OK);
	let body = reply.json();
	for (n, id) in ["self", "first", "last"].into_iter().enumerate() {
		method_error(&body, n, "invalidResultReference", id);
	}
	assert_eq!(
		body["methodResponses"][3],
		json!(["Core/echo", {"alive": true}, "after"])
	);
	h.healthy_api().await;
}

#[tokio::test]
async fn doubling_back_reference_chain_is_stopped_at_object_cap() {
	let h = Harness::new();
	let mut calls = vec![json!(["Core/echo", {"x": ["seed"]}, "c0"])];
	for n in 1..=10 {
		let prior = format!("c{}", n - 1);
		calls.push(json!(["Core/echo", {"x": {"#a": reference(&prior, "/x"), "#b": reference(&prior, "/x")}}, format!("c{n}")]));
	}
	let reply = h.jmap(Value::Array(calls)).await;
	assert_eq!(reply.status, StatusCode::OK);
	let body = reply.json();
	// c9 has 512 leaves; each reference in c10 would materialize 512 > 500.
	for n in 0..=9 {
		assert_eq!(body["methodResponses"][n][0], "Core/echo");
	}
	method_error(&body, 10, "requestTooLarge", "c10");
	h.healthy_api().await;
}

#[tokio::test]
async fn repeated_back_references_are_stopped_at_byte_budget() {
	let h = Harness::new();
	let wide: Vec<String> = (0..500).map(|n| format!("{n:01000}")).collect();
	let refs: serde_json::Map<String, Value> = (0..25)
		.map(|n| (format!("#k{n}"), reference("seed", "/ids")))
		.collect();
	let reply = h
		.jmap(json!([
			["Core/echo", {"ids": wide}, "seed"],
			["Core/echo", refs, "expand"],
		]))
		.await;
	assert_eq!(reply.status, StatusCode::OK);
	assert_eq!(reply.json()["methodResponses"][0][0], "Core/echo");
	method_error(&reply.json(), 1, "requestTooLarge", "expand");
	h.healthy_api().await;
}

#[tokio::test]
async fn deeply_nested_jmap_arguments_are_refused_by_json_parser() {
	let h = Harness::new();
	let body = format!(
		"{{\"methodCalls\":[[\"Core/echo\",{{\"x\":{}0{}}},\"deep\"]]}}",
		"[".repeat(100_000),
		"]".repeat(100_000)
	);
	let reply = call(
		&h.api,
		api_request("POST", "/jmap/api", ALICE, Body::from(body)),
	)
	.await;
	assert_eq!(reply.status, StatusCode::BAD_REQUEST);
	h.healthy_api().await;
}

#[tokio::test]
async fn request_body_over_max_size_is_refused() {
	let h = Harness::new();
	assert_eq!(advertised(&h, "maxSizeRequest").await, 10_000_000);
	let request = api_request("POST", "/jmap/api", ALICE, repeated_body(10_000_001));
	let reply = call(&h.api, request).await;
	assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
	assert_eq!(reply.json()["limit"], "maxSizeRequest");
	h.healthy_api().await;
}

#[tokio::test]
async fn giant_upload_is_refused_before_blob_persistence() {
	let h = Harness::new();
	assert_eq!(advertised(&h, "maxSizeUpload").await, UPLOAD_LIMIT);
	for size in [UPLOAD_LIMIT + 1, UPLOAD_LIMIT + 1024 * 1024] {
		let reply = call(
			&h.api,
			api_request("POST", "/jmap/upload/alice", ALICE, repeated_body(size)),
		)
		.await;
		assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
		assert_eq!(reply.json()["type"], "urn:ietf:params:jmap:error:limit");
		assert_eq!(reply.json()["limit"], "maxSizeUpload");
		assert!(!h.root().join("blobs/accounts/alice").exists());
		h.healthy_api().await;
	}
}

#[tokio::test]
async fn upload_at_limit_is_accepted_and_remains_readable() {
	let h = Harness::new();
	let reply = call(
		&h.api,
		api_request(
			"POST",
			"/jmap/upload/alice",
			ALICE,
			repeated_body(UPLOAD_LIMIT),
		),
	)
	.await;
	assert_eq!(reply.status, StatusCode::OK);
	let body = reply.json();
	assert_eq!(body["size"], UPLOAD_LIMIT);
	let id = body["blobId"].as_str().expect("blob id");
	let downloaded = call(
		&h.api,
		api_request(
			"GET",
			&format!("/jmap/download/alice/{id}/f"),
			ALICE,
			Body::empty(),
		),
	)
	.await;
	assert_eq!(downloaded.status, StatusCode::OK);
	assert_eq!(downloaded.body, vec![b'x'; UPLOAD_LIMIT]);
	h.healthy_api().await;
}
