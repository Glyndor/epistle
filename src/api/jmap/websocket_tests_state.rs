//! The states a WebSocket `StateChange` pushes (RFC 8887 §5, RFC 8620 §7.1)
//! are the change-journal states `*/get` and `*/changes` use, per type, so a
//! client can call `/changes` with what the push told it.

use super::{PushState, handle_ws_message};
use crate::api::Principal;
use crate::api::tests::test_state;
use serde_json::{Value, json};

fn principal() -> Principal {
	Principal::unrestricted()
}

/// Run one method call over the socket and return its response triple.
fn call(state: &crate::api::ApiState, push: &mut PushState, method: &str, args: Value) -> Value {
	let frame = json!({ "@type": "Request", "methodCalls": [[method, args, "c1"]] }).to_string();
	let frames = handle_ws_message(state, &principal(), &frame, push);
	let response: Value = serde_json::from_str(&frames[0]).expect("json");
	response["methodResponses"][0].clone()
}

/// Run one method call with push enabled and return the `StateChange` that
/// followed it, `Null` when none did.
fn pushed(state: &crate::api::ApiState, method: &str, args: Value) -> Value {
	let mut push = PushState::default();
	let enable = json!({ "@type": "WebSocketPushEnable" }).to_string();
	handle_ws_message(state, &principal(), &enable, &mut push);
	let frame = json!({ "@type": "Request", "methodCalls": [[method, args, "c1"]] }).to_string();
	let frames = handle_ws_message(state, &principal(), &frame, &mut push);
	frames
		.get(1)
		.map(|text| serde_json::from_str(text).expect("json"))
		.unwrap_or(Value::Null)
}

fn state_with_inbox(dir: &std::path::Path) -> crate::api::ApiState {
	std::fs::create_dir_all(dir.join("accounts").join("alice").join("new")).expect("mkdir");
	test_state(dir, 0)
}

#[test]
fn a_pushed_email_state_is_the_get_state_and_answers_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_inbox(dir.path());
	let mut quiet = PushState::default();
	let before = call(
		&state,
		&mut quiet,
		"Email/get",
		json!({ "accountId": "alice", "ids": [] }),
	);
	let before = before[1]["state"].as_str().expect("state").to_string();

	let change = pushed(
		&state,
		"Email/set",
		json!({
			"accountId": "alice",
			"create": { "d1": {
				"mailboxIds": { "INBOX": true },
				"from": [{ "email": "alice@example.org" }],
				"subject": "draft",
			} },
		}),
	);
	assert_eq!(change["@type"], "StateChange", "{change}");
	let states = &change["changed"]["alice"];

	for (kind, get, args) in [
		(
			"Email",
			"Email/get",
			json!({ "accountId": "alice", "ids": [] }),
		),
		(
			"Mailbox",
			"Mailbox/get",
			json!({ "accountId": "alice", "ids": [] }),
		),
		(
			"Thread",
			"Thread/get",
			json!({ "accountId": "alice", "ids": [] }),
		),
	] {
		let reply = call(&state, &mut quiet, get, args);
		assert_eq!(states[kind], reply[1]["state"], "{kind} pushed vs {get}");
	}

	// The pushed state is one `Email/changes` accepts, with nothing after it.
	let since = states["Email"].clone();
	let reply = call(
		&state,
		&mut quiet,
		"Email/changes",
		json!({ "accountId": "alice", "sinceState": since }),
	);
	assert_eq!(reply[0], "Email/changes", "{}", reply[1]);
	assert_eq!(reply[1]["newState"], since);
	assert_eq!(reply[1]["created"], json!([]));

	// And the client that held the earlier state reaches it with `/changes`.
	let reply = call(
		&state,
		&mut quiet,
		"Email/changes",
		json!({ "accountId": "alice", "sinceState": before }),
	);
	assert_eq!(reply[0], "Email/changes", "{}", reply[1]);
	assert_eq!(reply[1]["newState"], since);
	assert_eq!(reply[1]["created"].as_array().map(Vec::len), Some(1));
}

/// A change that moves the journal without changing stored bytes (a new
/// empty mailbox) is pushed too.
#[test]
fn a_new_mailbox_is_pushed_with_the_mailbox_get_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_inbox(dir.path());
	let change = pushed(
		&state,
		"Mailbox/set",
		json!({ "accountId": "alice", "create": { "k": { "name": "Projects" } } }),
	);
	assert_eq!(change["@type"], "StateChange", "{change}");
	let mut quiet = PushState::default();
	let reply = call(
		&state,
		&mut quiet,
		"Mailbox/get",
		json!({ "accountId": "alice" }),
	);
	assert_eq!(change["changed"]["alice"]["Mailbox"], reply[1]["state"]);
}
