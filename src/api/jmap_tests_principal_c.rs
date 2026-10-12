//! Principal-gate tests across every JMAP surface and both confined
//! credential kinds. A foreign account must get exactly the answer a
//! non-existent one gets, so a confined key learns nothing about which
//! accounts exist outside its reach.

use super::jmap_tests_principal_b::{key, state_with_key};
use super::router;
use super::tests::request_with_body;
use crate::api::Principal;
use crate::api::jmap::websocket::{PushState, handle_ws_message};
use crate::api::state::MatchedAuth;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "confined-secret";

/// The two confined credential kinds, both reaching `ann` and not `bob`.
fn confined_keys() -> [(&'static str, crate::api::api_keys::ApiKey); 2] {
	[
		("domains", key(SECRET, &["a.example"], None, None)),
		("account", key(SECRET, &[], Some("ann"), None)),
	]
}

/// Every account-scoped method, with the arguments that name `account`.
fn method_calls(account: &str) -> Vec<(&'static str, Value)> {
	vec![
		("Mailbox/get", json!({"accountId": account})),
		("Mailbox/query", json!({"accountId": account})),
		(
			"Mailbox/set",
			json!({"accountId": account, "create": {"k": {"name": "X"}}}),
		),
		(
			"Mailbox/changes",
			json!({"accountId": account, "sinceState": "0"}),
		),
		("Email/get", json!({"accountId": account, "ids": ["1"]})),
		("Email/query", json!({"accountId": account})),
		("Email/set", json!({"accountId": account, "update": {}})),
		(
			"Email/copy",
			json!({"accountId": account, "fromAccountId": "ann", "create": {}}),
		),
		("Thread/get", json!({"accountId": account, "ids": ["1"]})),
		("Identity/get", json!({"accountId": account})),
		("Quota/get", json!({"accountId": account})),
		(
			"EmailSubmission/set",
			json!({"accountId": account, "create": {}}),
		),
	]
}

async fn call(app: &Router, method: &str, args: Value) -> Value {
	let body = json!({"methodCalls": [[method, args, "c1"]]});
	let (status, response) =
		request_with_body(app, "POST", "/jmap/api", Some(SECRET), Some(body)).await;
	assert_eq!(status, StatusCode::OK, "{method}: {response}");
	response["methodResponses"][0].clone()
}

#[tokio::test]
async fn foreign_account_gets_the_same_refusal_as_a_missing_one_on_every_method() {
	for (kind, key) in confined_keys() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(state_with_key(dir.path(), key));
		for ((method, foreign), (_, missing)) in
			method_calls("bob").into_iter().zip(method_calls("nobody"))
		{
			let foreign = call(&app, method, foreign).await;
			let missing = call(&app, method, missing).await;
			assert_eq!(
				foreign[1]["type"], "accountNotFound",
				"{kind} key, {method} on a foreign account: {foreign}"
			);
			assert_eq!(
				foreign, missing,
				"{kind} key, {method}: a foreign account must look missing"
			);
		}
	}
}

#[tokio::test]
async fn foreign_copy_source_gets_the_same_refusal_as_a_missing_one() {
	for (kind, key) in confined_keys() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(state_with_key(dir.path(), key));
		let args = |from: &str| json!({"accountId": "ann", "fromAccountId": from, "create": {}});
		let foreign = call(&app, "Email/copy", args("bob")).await;
		let missing = call(&app, "Email/copy", args("nobody")).await;
		assert_eq!(
			foreign[1]["type"], "fromAccountNotFound",
			"{kind}: {foreign}"
		);
		assert_eq!(
			foreign, missing,
			"{kind}: a foreign source must look missing"
		);
	}
}

async fn send(
	app: &Router,
	method: &str,
	uri: &str,
	token: &str,
	body: &[u8],
) -> (StatusCode, Vec<u8>) {
	let request = Request::builder()
		.method(method)
		.uri(uri)
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.header(header::CONTENT_TYPE, "text/plain")
		.body(Body::from(body.to_vec()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, bytes.to_vec())
}

fn blob_id(body: &[u8]) -> String {
	let json: Value = serde_json::from_slice(body).expect("upload json");
	json["blobId"].as_str().expect("blobId").to_string()
}

#[tokio::test]
async fn upload_reaches_only_the_principals_accounts() {
	for (kind, key) in confined_keys() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(state_with_key(dir.path(), key));
		let (own, _) = send(&app, "POST", "/jmap/upload/ann", SECRET, b"mine").await;
		assert_eq!(
			own,
			StatusCode::OK,
			"{kind} key uploading to its own account"
		);
		let foreign = send(&app, "POST", "/jmap/upload/bob", SECRET, b"x").await;
		let missing = send(&app, "POST", "/jmap/upload/nobody", SECRET, b"x").await;
		assert_eq!(
			foreign.0,
			StatusCode::NOT_FOUND,
			"{kind} key uploading to bob"
		);
		assert_eq!(
			foreign, missing,
			"{kind}: a foreign upload target must look missing"
		);
	}
}

#[tokio::test]
async fn download_reaches_only_the_principals_accounts() {
	let admin = super::tests::TOKEN.as_str();
	for (kind, key) in confined_keys() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(state_with_key(dir.path(), key));
		let (_, ann_upload) = send(&app, "POST", "/jmap/upload/ann", admin, b"ann bytes").await;
		let (_, bob_upload) = send(&app, "POST", "/jmap/upload/bob", admin, b"bob bytes").await;
		let ann_blob = blob_id(&ann_upload);
		let bob_blob = blob_id(&bob_upload);

		let own = send(
			&app,
			"GET",
			&format!("/jmap/download/ann/{ann_blob}/f"),
			SECRET,
			b"",
		)
		.await;
		assert_eq!(
			own,
			(StatusCode::OK, b"ann bytes".to_vec()),
			"{kind} key, own blob"
		);
		let foreign = send(
			&app,
			"GET",
			&format!("/jmap/download/bob/{bob_blob}/f"),
			SECRET,
			b"",
		)
		.await;
		let missing = send(
			&app,
			"GET",
			&format!("/jmap/download/nobody/{bob_blob}/f"),
			SECRET,
			b"",
		)
		.await;
		assert_eq!(
			foreign.0,
			StatusCode::NOT_FOUND,
			"{kind} key reading bob's blob"
		);
		assert_eq!(
			foreign, missing,
			"{kind}: a foreign download must look missing"
		);
	}
}

#[tokio::test]
async fn websocket_requests_reach_only_the_principals_accounts() {
	for (kind, key) in confined_keys() {
		let dir = tempfile::tempdir().expect("tempdir");
		let state = state_with_key(dir.path(), key);
		let auth = MatchedAuth {
			token: Some(SECRET.to_string()),
			client_ip: None,
			configured: false,
		};
		let principal = Principal::for_token(&state, &auth);
		let frame = |account: &str| {
			json!({
				"@type": "Request",
				"methodCalls": [["Mailbox/get", {"accountId": account}, "c1"]],
			})
			.to_string()
		};
		let reply = |account: &str| -> Value {
			let frames = handle_ws_message(
				&state,
				&principal,
				&frame(account),
				&mut PushState::default(),
			);
			serde_json::from_str(&frames[0]).expect("frame is JSON")
		};
		assert_eq!(
			reply("ann")["methodResponses"][0][0],
			"Mailbox/get",
			"{kind}"
		);
		let foreign = reply("bob");
		assert_eq!(
			foreign["methodResponses"][0][1]["type"], "accountNotFound",
			"{kind} key over WebSocket: {foreign}"
		);
		assert_eq!(
			foreign,
			reply("nobody"),
			"{kind}: a foreign account must look missing"
		);
	}
}
