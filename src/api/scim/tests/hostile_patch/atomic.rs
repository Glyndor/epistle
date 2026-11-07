//! A PATCH is all or nothing, and what it costs is bounded by its passwords.
use super::{SCIM_KEY_SECRET, app, build_state};
use crate::api::tests::hostile_wire::{Peer, read};
use axum::http::StatusCode;
use serde_json::json;

async fn patch(peer: &Peer, operations: serde_json::Value) -> (StatusCode, serde_json::Value) {
	read(
		peer.client
			.patch(format!("{}/scim/v2/Users/victim", peer.base))
			.bearer_auth(SCIM_KEY_SECRET.as_str())
			.header("Content-Type", "application/scim+json")
			.body(
				json!({
					"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					"Operations": operations
				})
				.to_string(),
			)
			.send()
			.await
			.expect("PATCH response"),
	)
	.await
}

fn victim() -> (tempfile::TempDir, crate::api::ApiState) {
	let (dir, state) = build_state();
	state
		.store()
		.add(crate::directory_store::DynamicAccount {
			name: "victim".into(),
			addresses: vec!["victim@example.org".into()],
			..Default::default()
		})
		.unwrap();
	(dir, state)
}

#[tokio::test]
async fn an_operation_that_fails_leaves_the_earlier_ones_unapplied() {
	let (_dir, state) = victim();
	let peer = Peer::start(app(state.clone())).await;
	let before = state
		.store()
		.dynamic("victim")
		.unwrap()
		.password_hash
		.clone();
	let (status, body) = patch(
		&peer,
		json!([
			{"op": "replace", "path": "password", "value": "A-new-passphrase-1"},
			{"op": "replace", "path": "active", "value": false},
			{"op": "remove", "path": "active"}
		]),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let after = state.store().dynamic("victim").unwrap();
	assert_eq!(after.password_hash, before, "the password was not changed");
	assert!(!after.disabled, "the account was not disabled");
}

#[tokio::test]
async fn more_than_three_passwords_are_refused_before_any_is_hashed() {
	let (_dir, state) = victim();
	let peer = Peer::start(app(state)).await;
	let change = |n: usize| json!({"op": "replace", "path": "password", "value": format!("A-new-passphrase-{n}")});
	let (status, body) = patch(&peer, json!([change(1)])).await;
	assert_eq!(status, StatusCode::OK, "one password: {body}");
	let (status, body) = patch(&peer, json!([change(1), change(2), change(3), change(4)])).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "four passwords: {body}");
}
