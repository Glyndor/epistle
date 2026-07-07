//! JMAP over WebSocket tests (RFC 8887) and PushSubscription tests (RFC 8620
//! §7.2). The frame handling is exercised through the pure `handle_ws_message`
//! with JSON strings — no live WebSocket client is needed.

use super::{PushState, handle_ws_message};
use crate::api::router;
use crate::api::tests::{TOKEN, request, test_state};
use axum::http::StatusCode;
use serde_json::{Value, json};

/// Parse the single reply frame, asserting exactly one was produced.
fn one(frames: Vec<String>) -> Value {
	assert_eq!(frames.len(), 1, "expected one frame, got {frames:?}");
	serde_json::from_str(&frames[0]).expect("frame is JSON")
}

#[test]
fn request_frame_returns_response_with_echoed_request_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();
	let frame = json!({
		"@type": "Request",
		"id": "R1",
		"using": ["urn:ietf:params:jmap:core"],
		"methodCalls": [["Core/echo", {"hello": "ws"}, "c1"]],
	})
	.to_string();
	let reply = one(handle_ws_message(&state, &frame, &mut push));
	assert_eq!(reply["@type"], "Response");
	assert_eq!(reply["requestId"], "R1");
	assert_eq!(reply["methodResponses"][0][0], "Core/echo");
	assert_eq!(reply["methodResponses"][0][1]["hello"], "ws");
	assert_eq!(reply["methodResponses"][0][2], "c1");
}

#[test]
fn request_without_id_omits_request_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();
	let frame = json!({
		"@type": "Request",
		"methodCalls": [["Core/echo", {}, "c1"]],
	})
	.to_string();
	let reply = one(handle_ws_message(&state, &frame, &mut push));
	assert_eq!(reply["@type"], "Response");
	assert!(reply.get("requestId").is_none(), "{reply}");
}

#[test]
fn unknown_type_returns_request_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();
	let reply = one(handle_ws_message(
		&state,
		&json!({"@type": "Frobnicate"}).to_string(),
		&mut push,
	));
	assert_eq!(reply["@type"], "RequestError");
	assert_eq!(reply["type"], "urn:ietf:params:jmap:error:unknownType");
	assert_eq!(reply["status"], 400);
}

#[test]
fn unparseable_frame_returns_request_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();
	let reply = one(handle_ws_message(&state, "{not json", &mut push));
	assert_eq!(reply["@type"], "RequestError");
	assert_eq!(reply["type"], "urn:ietf:params:jmap:error:notJSON");
}

#[test]
fn push_enable_then_mailbox_set_yields_state_change() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();

	// Opt the connection in (no dataTypes => all types).
	let enable = handle_ws_message(
		&state,
		&json!({"@type": "WebSocketPushEnable"}).to_string(),
		&mut push,
	);
	assert!(enable.is_empty(), "enable should not reply: {enable:?}");

	// A /set that adds an Email changes the account state token. Use Email/set to
	// create a draft so stored bytes grow.
	let frame = json!({
		"@type": "Request",
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"create": { "d1": {
				"mailboxIds": {"INBOX": true},
				"from": [{"email": "alice@example.org"}],
				"subject": "draft",
			} },
		}, "c1"]],
	})
	.to_string();
	let frames = handle_ws_message(&state, &frame, &mut push);
	assert_eq!(frames.len(), 2, "Response + StateChange: {frames:?}");
	let response: Value = serde_json::from_str(&frames[0]).expect("json");
	assert_eq!(response["@type"], "Response");
	let change: Value = serde_json::from_str(&frames[1]).expect("json");
	assert_eq!(change["@type"], "StateChange");
	assert!(change["changed"]["alice"]["Email"].is_string(), "{change}");
	assert!(
		change["changed"]["alice"]["Mailbox"].is_string(),
		"{change}"
	);
}

#[test]
fn push_disabled_suppresses_state_change() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();
	let frame = json!({
		"@type": "Request",
		"methodCalls": [["Email/set", {
			"accountId": "alice",
			"create": { "d1": {
				"mailboxIds": {"INBOX": true},
				"from": [{"email": "alice@example.org"}],
				"subject": "draft",
			} },
		}, "c1"]],
	})
	.to_string();
	// Push not enabled: only the Response, never a StateChange.
	let frames = handle_ws_message(&state, &frame, &mut push);
	assert_eq!(frames.len(), 1, "{frames:?}");
}

#[test]
fn push_subscription_set_then_get_round_trips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();

	let set = json!({
		"@type": "Request",
		"methodCalls": [["PushSubscription/set", {
			"create": { "s1": {
				"deviceClientId": "dev1",
				"url": "https://push.example/endpoint",
				"types": ["Email"],
			} },
		}, "c1"]],
	})
	.to_string();
	let reply = one(handle_ws_message(&state, &set, &mut push));
	let id = reply["methodResponses"][0][1]["created"]["s1"]["id"]
		.as_str()
		.expect("created id")
		.to_string();

	let get = json!({
		"@type": "Request",
		"methodCalls": [["PushSubscription/get", {"ids": null}, "c2"]],
	})
	.to_string();
	let reply = one(handle_ws_message(&state, &get, &mut push));
	let list = reply["methodResponses"][0][1]["list"]
		.as_array()
		.expect("list");
	assert_eq!(list.len(), 1);
	assert_eq!(list[0]["id"], id);
	assert_eq!(list[0]["url"], "https://push.example/endpoint");
}

#[test]
fn push_subscription_set_rejects_missing_url() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();
	let set = json!({
		"@type": "Request",
		"methodCalls": [["PushSubscription/set", {
			"create": { "bad": {"deviceClientId": "d"} },
		}, "c1"]],
	})
	.to_string();
	let reply = one(handle_ws_message(&state, &set, &mut push));
	assert_eq!(
		reply["methodResponses"][0][1]["notCreated"]["bad"]["type"],
		"invalidProperties"
	);
}

#[test]
fn push_subscription_destroy_removes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0);
	let mut push = PushState::default();
	let set = json!({
		"@type": "Request",
		"methodCalls": [["PushSubscription/set", {
			"create": { "s1": {"url": "https://x.example/p"} },
		}, "c1"]],
	})
	.to_string();
	let reply = one(handle_ws_message(&state, &set, &mut push));
	let id = reply["methodResponses"][0][1]["created"]["s1"]["id"]
		.as_str()
		.expect("id")
		.to_string();
	let destroy = json!({
		"@type": "Request",
		"methodCalls": [["PushSubscription/set", {"destroy": [id]}, "c2"]],
	})
	.to_string();
	let reply = one(handle_ws_message(&state, &destroy, &mut push));
	assert_eq!(reply["methodResponses"][0][1]["destroyed"][0], id);
	assert!(state.push_subscriptions().is_empty());
}

#[tokio::test]
async fn session_advertises_websocket_capability() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert_eq!(status, StatusCode::OK);
	let ws = &body["capabilities"]["urn:ietf:params:jmap:websocket"];
	assert_eq!(ws["url"], "/jmap/ws", "{body}");
	assert_eq!(ws["supportsPush"], true, "{body}");
}
