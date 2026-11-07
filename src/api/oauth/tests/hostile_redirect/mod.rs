//! The headless authorize endpoint must reject hostile redirect parameters.
mod bound;

use super::base::{keys, state_with_authz};
use crate::api::tests::hostile_wire::{Peer, supervised};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn hostile_redirect_uri_is_rejected_on_wire() {
	if supervised(module_path!(), "hostile_redirect_uri_is_rejected_on_wire") {
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let peer = Peer::start(crate::api::router(state.clone())).await;
	let oversize = format!("https://app.example/{}", "x".repeat(3000));
	for uri in [
		"javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
		"data:text/html,x",
		"//evil.example/capture",
		"https://mail.example/\r\nLocation: https://evil.example",
		oversize.as_str(),
	] {
		let (status, body) = peer
			.json(
				"/oauth/authorize",
				json!({
					"client_id": "cli", "login": "alice@example.org",
					"password": crate::test_fixtures::password(),
					"code_challenge_method": "S256", "code_challenge": "A".repeat(43),
					"redirect_uri": uri
				}),
			)
			.await;
		assert_eq!(
			status,
			StatusCode::BAD_REQUEST,
			"redirect_uri={uri:?}: {body}"
		);
		assert_eq!(body["error"], "invalid_request");
		assert!(body.get("code").is_none());
		assert!(state.authz().unwrap().codes.lock().unwrap().is_empty());
	}
	// An absolute https URI is only echoed by clients that always send one:
	// the endpoint answers with JSON and never redirects, so it is not
	// refused, and no response redirects anywhere.
	let (status, body) = peer
		.json(
			"/oauth/authorize",
			json!({
				"client_id": "cli", "login": "alice@example.org",
				"password": crate::test_fixtures::password(),
				"code_challenge_method": "S256", "code_challenge": "A".repeat(43),
				"redirect_uri": "https://app.example/callback"
			}),
		)
		.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(body.get("code").is_some(), "{body}");
	peer.healthy().await;
}
