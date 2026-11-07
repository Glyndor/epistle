//! A sub-2-MiB request must not bypass an operation-count budget.
use super::base::{SCIM_KEY_SECRET, app, build_state};
use crate::api::tests::hostile_wire::{Peer, read, supervised};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn ten_thousand_patch_operations_are_rejected_on_wire() {
	if supervised(
		module_path!(),
		"ten_thousand_patch_operations_are_rejected_on_wire",
	) {
		return;
	}
	let (_dir, state) = build_state();
	state
		.store()
		.add(crate::directory_store::DynamicAccount {
			name: "victim".into(),
			addresses: vec!["victim@example.org".into()],
			disabled: false,
			..Default::default()
		})
		.unwrap();
	let peer = Peer::start(app(state.clone())).await;
	// Positive control: one operation reaches the mutator with these credentials.
	let (status, body) = read(
		peer.client
			.patch(format!("{}/scim/v2/Users/victim", peer.base))
			.bearer_auth(SCIM_KEY_SECRET.as_str())
			.header("Content-Type", "application/scim+json")
			.body(
				json!({
					"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					"Operations": [{"op": "replace", "path": "active", "value": true}]
				})
				.to_string(),
			)
			.send()
			.await
			.expect("single valid PATCH response"),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "single operation: {body}");
	assert_eq!(body["active"], true);
	// All operations are individually valid. An unsupported first operation
	// would hide a missing count guard behind an unrelated 400.
	let operations: Vec<_> = (0..10_000)
		.map(|n| json!({"op": "replace", "path": "active", "value": n % 2 == 0}))
		.collect();
	let body = json!({
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": operations
	})
	.to_string();
	assert!(
		body.len() < 1024 * 1024,
		"exercise operation budget, not default body cap"
	);
	let (status, body) = read(
		peer.client
			.patch(format!("{}/scim/v2/Users/victim", peer.base))
			.bearer_auth(SCIM_KEY_SECRET.as_str())
			.header("Content-Type", "application/scim+json")
			.body(body)
			.send()
			.await
			.expect("bounded SCIM PATCH response"),
	)
	.await;
	assert!(
		matches!(
			status,
			StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE
		),
		"10k valid operations: {status}: {body}"
	);
	assert_eq!(body["status"], status.as_u16().to_string());
	assert_eq!(
		body["schemas"][0],
		"urn:ietf:params:scim:api:messages:2.0:Error"
	);
	assert!(
		!state.store().dynamic("victim").unwrap().disabled,
		"rejection must precede any operation"
	);
	peer.healthy().await;
}
