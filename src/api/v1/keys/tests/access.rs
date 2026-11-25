//! Who may use the key routes: the `key` scope, and never a key bound to an
//! account.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

fn routes() -> Vec<(&'static str, &'static str, Option<serde_json::Value>)> {
	vec![
		("GET", "/api/v1/keys", None),
		(
			"POST",
			"/api/v1/keys",
			Some(json!({"label": "child", "scopes": ["read"]})),
		),
		("DELETE", "/api/v1/keys/of-a", None),
	]
}

#[tokio::test]
async fn a_request_without_the_key_scope_is_refused() {
	let world = world();
	for (method, path, body) in routes() {
		let (status, _, reply) = call(&world.state, method, path, PLAIN, body).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {reply}");
	}
	assert_eq!(labels(&world).len(), 7, "nothing was made or revoked");
}

#[tokio::test]
async fn a_key_bound_to_an_account_is_refused() {
	let world = world();
	for (method, path, body) in routes() {
		let (status, _, reply) = call(&world.state, method, path, BOUND, body).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {reply}");
	}
	assert_eq!(labels(&world).len(), 7);
}

#[tokio::test]
async fn a_request_without_a_credential_or_with_a_wrong_one_is_refused() {
	let world = world();
	for bearer in ["nope", ""] {
		let (status, _, _) = call(&world.state, "GET", "/api/v1/keys", bearer, None).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{bearer:?}");
	}
}

#[tokio::test]
async fn the_configured_token_and_a_key_with_the_scope_reach_the_routes() {
	let world = world();
	for secret in [token(), MAKER, MAKER_A] {
		let (status, _, body) = call(&world.state, "GET", "/api/v1/keys", secret, None).await;
		assert_eq!(status, StatusCode::OK, "{body}");
	}
}
