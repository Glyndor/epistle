//! A SCIM write decides on the account as the write finds it, not as the
//! request first read it.
//!
//! A second handle on the same data directory writes the account the way a
//! command run beside the server does: the file changes and the server's
//! copy in memory does not. The request that follows reads the old copy and
//! then writes over the new file, so the order of the two is fixed without
//! any waiting.

use std::collections::HashMap;

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::api::ApiState;
use crate::api::audit::tests::base::{audit_events, run_with_capture};
use crate::config::Protocol;
use crate::directory_store::{AccountStore, DynamicAccount, Switch};

use super::base::{SCIM_KEY_SECRET, app, build_state, send};

const OWN: &str = "frank@example.org";
const ADDED: &str = "frank.second@example.org";

/// A server with the account `frank`, and a second handle on its files.
fn two_writers(disabled: bool) -> (tempfile::TempDir, ApiState, AccountStore) {
	let (dir, state) = build_state();
	state
		.store()
		.add(DynamicAccount {
			name: "frank".to_string(),
			addresses: vec![OWN.to_string()],
			disabled,
			..DynamicAccount::default()
		})
		.expect("add frank");
	let other = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		HashMap::new(),
		Vec::new(),
	)
	.expect("second handle");
	(dir, state, other)
}

/// The account as the server holds it in memory.
fn held(state: &ApiState) -> DynamicAccount {
	state.store().dynamic("frank").expect("frank")
}

/// A request body that asks for `active`, as `method` spells it.
fn asking(method: &str, active: bool) -> Value {
	match method {
		"PUT" => json!({
			"userName": "frank",
			"active": active,
			"emails": [{"value": OWN}],
		}),
		_ => json!({
			"Operations": [{"op": "replace", "path": "active", "value": active}]
		}),
	}
}

/// The audit lines a `method` request on `frank` writes.
fn lines_of(state: &ApiState, method: &str, body: &Value) -> Vec<String> {
	let app = app(state.clone());
	let events = run_with_capture(async {
		let (status, answer) = send(
			&app,
			method,
			"/scim/v2/Users/frank",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(body),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{answer}");
	});
	audit_events(&events)
		.iter()
		.map(|event| event.fields.get("event").cloned().unwrap_or_default())
		.collect()
}

/// The `account.disabled` or `account.enabled` line is written when the
/// write itself changes the state, whatever the request read before it.
#[tokio::test(flavor = "multi_thread")]
async fn the_suspension_line_follows_the_state_the_write_found() {
	// The state the request reads, the one another writer leaves before the
	// write, the one the request asks for, and the lines owed.
	let rows: [(bool, bool, bool, &[&str]); 4] = [
		(false, true, true, &["account.enabled"]),
		(false, true, false, &[]),
		(true, false, false, &["account.disabled"]),
		(true, false, true, &[]),
	];
	// Every row is tried before judging, so a failure names all that differ.
	let mut wrong = Vec::new();
	for method in ["PUT", "PATCH"] {
		for (read, found, active, owed) in rows {
			let (_dir, state, other) = two_writers(read);
			other.set_disabled("frank", found).expect("other writer");
			assert_eq!(held(&state).disabled, read, "the server's copy is old");

			let lines = lines_of(&state, method, &asking(method, active));

			assert_eq!(held(&state).disabled, !active, "{method} wrote");
			if lines != owed {
				wrong.push(format!(
					"{method} read disabled={read}, found disabled={found}, \
					 asked active={active}: wrote {lines:?}, owed {owed:?}"
				));
			}
		}
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Everything another writer can change about the account.
fn change_everything(other: &AccountStore) {
	other.add_address("frank", ADDED).expect("address");
	other
		.set_quota_bytes("frank", Some(5_000_000))
		.expect("quota");
	other
		.add_forward("frank", "away@elsewhere.example")
		.expect("forward");
	other
		.add_catch_all("frank", "example.org")
		.expect("catch-all");
	other.set_save_sent("frank", false).expect("save_sent");
	other
		.set_switch("frank", Switch::Send, false)
		.expect("send");
	other
		.set_switch("frank", Switch::Receive, false)
		.expect("receive");
	other
		.set_allowed_protocols("frank", Some(vec![Protocol::Imaps]))
		.expect("protocols");
}

/// The settings SCIM does not model are the ones another writer left.
fn assert_settings_kept(kept: &DynamicAccount) {
	assert_eq!(kept.quota_bytes, Some(5_000_000));
	assert_eq!(kept.forward, ["away@elsewhere.example"]);
	assert_eq!(kept.catch_all, ["example.org"]);
	assert_eq!(kept.save_sent, Some(false));
	assert_eq!(kept.send, Some(false));
	assert_eq!(kept.receive, Some(false));
	assert_eq!(kept.allowed_protocols, Some(vec![Protocol::Imaps]));
}

/// A `PUT` that names no address keeps the addresses and the settings the
/// account holds when it is written.
#[tokio::test(flavor = "multi_thread")]
async fn put_keeps_what_another_writer_changed_since_the_account_was_read() {
	let (_dir, state, other) = two_writers(false);
	change_everything(&other);
	assert_eq!(held(&state).quota_bytes, None, "the server's copy is old");
	assert_eq!(held(&state).addresses, [OWN]);

	lines_of(&state, "PUT", &json!({"userName": "frank", "active": true}));

	let kept = held(&state);
	assert_eq!(kept.addresses, [OWN, ADDED]);
	assert_settings_kept(&kept);
}

/// A `PUT` that names its addresses sets them, and still keeps the settings
/// another writer left.
#[tokio::test(flavor = "multi_thread")]
async fn put_that_names_addresses_sets_them_over_another_writer() {
	let (_dir, state, other) = two_writers(false);
	change_everything(&other);
	assert_eq!(held(&state).quota_bytes, None, "the server's copy is old");

	lines_of(&state, "PUT", &asking("PUT", true));

	let kept = held(&state);
	assert_eq!(kept.addresses, [OWN]);
	assert_settings_kept(&kept);
}
