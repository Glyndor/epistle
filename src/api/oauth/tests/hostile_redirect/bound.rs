//! A code issued for a redirect_uri is redeemed with the same one.
use super::super::base::{keys, state_with_authz};
use crate::api::tests::hostile_wire::Peer;
use axum::http::StatusCode;
use base64::Engine;
use serde_json::json;

fn challenge(verifier: &str) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

async fn code(peer: &Peer, verifier: &str, redirect_uri: Option<&str>) -> String {
	let mut request = json!({
		"client_id": "cli", "login": "alice@example.org",
		"password": crate::test_fixtures::password(),
		"code_challenge_method": "S256", "code_challenge": challenge(verifier)
	});
	if let Some(uri) = redirect_uri {
		request["redirect_uri"] = uri.into();
	}
	let (status, body) = peer.json("/oauth/authorize", request).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["code"].as_str().expect("code").to_string()
}

async fn redeem(
	peer: &Peer,
	code: &str,
	verifier: &str,
	redirect_uri: Option<&str>,
) -> (StatusCode, serde_json::Value) {
	let mut request = json!({
		"grant_type": "authorization_code", "code": code, "code_verifier": verifier
	});
	if let Some(uri) = redirect_uri {
		request["redirect_uri"] = uri.into();
	}
	peer.json("/oauth/token", request).await
}

#[tokio::test]
async fn a_code_is_redeemed_only_with_the_redirect_uri_it_was_issued_for() {
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let peer = Peer::start(crate::api::router(state)).await;
	let verifier = "v".repeat(64);
	let uri = "https://app.example/callback";
	for (given, label) in [
		(None, "none"),
		(Some("https://evil.example/callback"), "another"),
	] {
		let issued = code(&peer, &verifier, Some(uri)).await;
		let (status, body) = redeem(&peer, &issued, &verifier, given).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {body}");
		assert_eq!(body["error"], "invalid_grant", "{label}");
	}
	let issued = code(&peer, &verifier, Some(uri)).await;
	let (status, body) = redeem(&peer, &issued, &verifier, Some(uri)).await;
	assert_eq!(status, StatusCode::OK, "the same uri: {body}");
	// A code issued without one needs none.
	let issued = code(&peer, &verifier, None).await;
	let (status, body) = redeem(&peer, &issued, &verifier, None).await;
	assert_eq!(status, StatusCode::OK, "no uri either side: {body}");
}
