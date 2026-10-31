//! The JMAP surface under a key confined to one tenant, over the transports
//! the clients really use: the HTTP envelope, the WebSocket and the event
//! source. Each transport reaches the same decision, so a tenant key answers
//! for its own accounts and for no other.

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::super::jmap_email::jmap_eventsource::{next_event, open as open_eventsource};
use super::base::{TOKEN, request, request_raw, request_with_body};
use super::confinement::{TENANT_A, world};
use super::jmap_ws_revoke::Client;
use super::router;

/// `POST /jmap/api` with the tenant key, one method call.
async fn jmap(app: &axum::Router, method: &str, args: Value) -> Value {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(TENANT_A),
		Some(json!({ "methodCalls": [[method, args, "c1"]] })),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0].clone()
}

/// `POST /jmap/upload/{accountId}` with the raw body the route expects.
async fn upload(app: &axum::Router, bearer: &str, account: &str) -> (StatusCode, Value) {
	let request = axum::http::Request::builder()
		.method("POST")
		.uri(format!("/jmap/upload/{account}"))
		.header(
			axum::http::header::AUTHORIZATION,
			format!("Bearer {bearer}"),
		)
		.body(axum::body::Body::from("blob".as_bytes().to_vec()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(Value::Null),
	)
}

/// The tenant's own account is served, the other tenant's is not found.
#[tokio::test]
async fn the_jmap_envelope_serves_the_own_account_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let own = jmap(&app, "Mailbox/get", json!({ "accountId": "ann" })).await;
	assert_eq!(own[0], "Mailbox/get", "{own}");
	let foreign = jmap(&app, "Mailbox/get", json!({ "accountId": "bob" })).await;
	assert_eq!(foreign[1]["type"], "accountNotFound", "{foreign}");
}

/// The session resource advertises only the accounts the key may act for.
#[tokio::test]
async fn the_jmap_session_advertises_the_own_account_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let (status, body) = request(&app, "GET", "/jmap/session", Some(TENANT_A)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let accounts = body["accounts"].as_object().expect("accounts");
	assert_eq!(accounts.len(), 1, "{body}");
	assert!(accounts.contains_key("ann"), "{body}");
}

/// The same answer over the real WebSocket transport.
#[tokio::test]
async fn the_websocket_refuses_the_other_tenants_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut client = Client::open(world(dir.path()), TENANT_A).await;
	let frame = json!({
		"@type": "Request",
		"id": "w1",
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/get", { "accountId": "bob" }, "c1"]],
	});
	client.send(&frame).await;
	let reply = client.next_json().await;
	assert_eq!(reply["@type"], "Response", "{reply}");
	assert_eq!(
		reply["methodResponses"][0][1]["type"], "accountNotFound",
		"{reply}"
	);

	// The own account is still served on the same socket.
	let own = json!({
		"@type": "Request",
		"id": "w2",
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/get", { "accountId": "ann" }, "c1"]],
	});
	client.send(&own).await;
	let reply = client.next_json().await;
	assert_eq!(reply["@type"], "Response", "{reply}");
	assert_eq!(reply["methodResponses"][0][0], "Mailbox/get", "{reply}");
}

/// The event source pushes the state of the own account only.
#[tokio::test]
async fn the_event_source_pushes_the_own_account_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let (status, body) = open_eventsource(&app, TENANT_A, "types=*&closeafter=state&ping=0").await;
	assert_eq!(status, StatusCode::OK);
	let mut stream = body.into_data_stream();
	// A change in the other tenant must not reach this stream.
	let foreign = json!({ "methodCalls": [[
		"Mailbox/set", { "accountId": "bob", "create": { "n": { "name": "Work" } } }, "c"
	]] });
	let (_, reply) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(foreign),
	)
	.await;
	assert_eq!(reply["methodResponses"][0][0], "Mailbox/set", "{reply}");
	// The own account changes and the event arrives.
	let own = json!({ "methodCalls": [[
		"Mailbox/set", { "accountId": "ann", "create": { "n": { "name": "Work" } } }, "c"
	]] });
	let (_, reply) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(own)).await;
	assert_eq!(reply["methodResponses"][0][0], "Mailbox/set", "{reply}");
	let (name, data) = next_event(&mut stream).await.expect("a state event");
	assert_eq!(name, "state");
	let changed = data["changed"].as_object().expect("changed");
	assert_eq!(changed.len(), 1, "{data}");
	assert!(changed.contains_key("ann"), "{data}");
}

/// The upload route stores a blob in the account's own partition, and refuses
/// an account the key may not act for.
#[tokio::test]
async fn the_upload_route_takes_the_own_account_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let (status, body) = upload(&app, TENANT_A, "bob").await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	assert_eq!(
		body["type"], "urn:ietf:params:jmap:error:notFound",
		"{body}"
	);
	let (status, body) = upload(&app, TENANT_A, "ann").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["accountId"], "ann", "{body}");
}

/// The download route answers the same for a foreign account: a blob that
/// really exists in the other tenant's partition is not served.
#[tokio::test]
async fn the_download_route_refuses_the_other_tenants_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	// A blob in the other tenant's partition, stored by the administrator.
	let (status, body) = upload(&app, TOKEN.as_str(), "bob").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let blob = body["blobId"].as_str().expect("blobId").to_string();
	let path = format!("/jmap/download/bob/{blob}/blob.bin");
	let (status, body) = request(&app, "GET", &path, Some(TENANT_A)).await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	assert_eq!(
		body["type"], "urn:ietf:params:jmap:error:notFound",
		"{body}"
	);
	// The administrator downloads it, so the blob was really there.
	let (status, bytes) = request_raw(&app, &path, Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK, "{status}");
	assert_eq!(bytes, b"blob");
}
