//! Who may use the ban routes: the `ban` scope, and only that, and never a
//! key that is confined to domains or bound to an account.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;
use crate::antispam::bans::operator::tests::fake::FakeAdmin;

/// Every route and method the ban routes answer, with a body where one is needed.
fn routes() -> Vec<(&'static str, &'static str, Option<serde_json::Value>)> {
	vec![
		("GET", "/api/v1/bans", None),
		(
			"POST",
			"/api/v1/bans",
			Some(json!({"target": "203.0.113.9"})),
		),
		("DELETE", "/api/v1/bans/203.0.113.9", None),
		("GET", "/api/v1/bans/allow", None),
		(
			"POST",
			"/api/v1/bans/allow",
			Some(json!({"cidr": "10.1.0.0/16"})),
		),
		("DELETE", "/api/v1/bans/allow/10.1.0.0%2F16", None),
	]
}

#[tokio::test]
async fn a_request_without_a_credential_is_refused() {
	let world = world();
	for (method, path, body) in routes() {
		let app = crate::api::router(world.state.clone());
		let (status, _) =
			crate::api::tests::base::request_with_body(&app, method, path, None, body).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
	}
	assert_eq!(world.store.calls(), 0);
}

/// `read` and `write` do not open the routes, and neither does a key that
/// holds every other scope.
#[tokio::test]
async fn a_key_without_the_ban_scope_is_refused_on_every_route() {
	let world = world();
	for secret in [READER, OTHERS] {
		for (method, path, body) in routes() {
			let (status, reply) = call(&world, method, path, secret, body).await;
			assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {reply}");
		}
	}
	assert_eq!(world.store.calls(), 0, "the store was not reached");
	assert!(world.store.writes().is_empty());
}

/// The bans belong to the server: a key confined to a domain, or bound to an
/// account, is turned away and the store is not reached.
#[tokio::test]
async fn a_confined_or_bound_key_is_refused_on_every_route() {
	let world = world();
	for secret in [CONFINED, BOUND] {
		for (method, path, body) in routes() {
			let (status, reply) = call(&world, method, path, secret, body).await;
			assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {reply}");
		}
	}
	assert_eq!(world.store.calls(), 0, "the store was not reached");
	assert!(world.store.writes().is_empty());
}

#[tokio::test]
async fn the_ban_key_and_the_configured_token_reach_every_route() {
	for secret in [BANNER, token()] {
		let world = world();
		for (method, path, body) in routes() {
			let (status, reply) = call(&world, method, path, secret, body).await;
			assert!(
				status.is_success() || status == StatusCode::NOT_FOUND,
				"{method} {path}: {status} {reply}"
			);
			assert_ne!(status, StatusCode::FORBIDDEN, "{method} {path}");
		}
	}
}

/// A server with no database cannot manage bans, and says why.
#[tokio::test]
async fn without_a_database_the_routes_say_bans_are_not_manageable() {
	let world = build(Arc::new(FakeAdmin::default()), false);
	for (method, path, body) in routes() {
		let (status, reply) = call(&world, method, path, BANNER, body).await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {reply}");
		assert!(
			reply["error"]["message"]
				.as_str()
				.is_some_and(|text| text.contains("no [database] is configured")),
			"{reply}"
		);
	}
}
