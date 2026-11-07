//! A matching SHA256 is not permission to accept an oversized PKCE verifier.
use super::base::{keys, state_with_authz};
use crate::api::tests::hostile_wire::{Peer, supervised};
use axum::http::StatusCode;
use base64::Engine;
use serde_json::json;

#[tokio::test]
async fn megabyte_pkce_verifier_is_rejected_on_wire() {
	if supervised(module_path!(), "megabyte_pkce_verifier_is_rejected_on_wire") {
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let peer = Peer::start(crate::api::router(state)).await;
	let verifier = "v".repeat(1024 * 1024);
	let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
	let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());
	let (status, authorized) = peer
		.json(
			"/oauth/authorize",
			json!({
				"client_id": "cli", "login": "alice@example.org",
				"password": crate::test_fixtures::password(),
				"code_challenge_method": "S256", "code_challenge": challenge
			}),
		)
		.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"valid-sized S256 challenge: {authorized}"
	);
	let code = authorized["code"].as_str().expect("authorization code");
	let (status, body) = peer
		.json(
			"/oauth/token",
			json!({
				"grant_type": "authorization_code", "code": code, "code_verifier": verifier
			}),
		)
		.await;
	assert_eq!(
		status,
		StatusCode::BAD_REQUEST,
		"oversized matching verifier: {body}"
	);
	assert_eq!(body["error"], "invalid_grant");
	assert!(body.get("access_token").is_none());
	peer.healthy().await;
}
