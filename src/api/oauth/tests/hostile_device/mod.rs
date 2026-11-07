//! A single unauthenticated TCP origin cannot grow the device grant map.
use super::base::{keys, state_with_authz};
use crate::api::tests::hostile_wire::{Peer, supervised};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn device_code_flood_is_bounded_on_wire() {
	if supervised(module_path!(), "device_code_flood_is_bounded_on_wire") {
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let peer = Peer::start(crate::api::router(state.clone())).await;
	for n in 0..256 {
		// Rotating client_id must not evade the origin cap.
		let (status, body) = peer
			.json(
				"/oauth/device_authorization",
				json!({"client_id": format!("attacker-{n}")}),
			)
			.await;
		if n < 10 {
			assert_eq!(status, StatusCode::OK, "{body}");
			assert!(body["device_code"].is_string());
		} else {
			assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "request {n}: {body}");
			assert_eq!(body["error"], "slow_down");
			assert!(body.get("device_code").is_none());
		}
		assert_eq!(
			state.authz().unwrap().devices.lock().unwrap().len(),
			(n + 1).min(10)
		);
	}
	peer.healthy().await;
}
