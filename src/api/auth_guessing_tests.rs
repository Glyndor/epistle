//! What a wrong bearer token costs, and what a right one cannot undo: guesses
//! are bounded per client and a valid call does not give the budget back, a
//! malformed token is refused before any hashing, and the legacy argon2 check
//! of the configured token is not a free CPU burner.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::time::Duration;
use tower::ServiceExt;

use super::state::{CONFIGURED_ARGON2_RUNS, CONFIGURED_HASH_CHECKS};
use super::tests::{TOKEN, test_state};
use super::*;

async fn get(app: &axum::Router, token: &str, peer: &str) -> StatusCode {
	let mut request = Request::builder()
		.method("GET")
		.uri("/api/v1/domains")
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.body(Body::empty())
		.expect("request");
	let peer: std::net::IpAddr = peer.parse().expect("peer");
	request
		.extensions_mut()
		.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			peer, 4000,
		))));
	app.clone()
		.oneshot(request)
		.await
		.expect("response")
		.status()
}

fn app() -> axum::Router {
	let dir = tempfile::tempdir().expect("tempdir");
	router(test_state(&dir.keep(), 0).with_auth_window(Duration::from_secs(3600)))
}

#[tokio::test]
async fn a_valid_call_does_not_give_the_clients_failures_back() {
	let app = app();
	// Nineteen wrong tokens, one right one, then the twentieth wrong one: the
	// right one must not have started the count over.
	for _ in 0..19 {
		get(&app, "wrong", "198.51.100.1").await;
	}
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.1").await,
		StatusCode::OK
	);
	assert_eq!(
		get(&app, "wrong", "198.51.100.1").await,
		StatusCode::UNAUTHORIZED
	);
	assert_eq!(
		get(&app, "wrong", "198.51.100.1").await,
		StatusCode::TOO_MANY_REQUESTS,
		"twenty failures stand however many right tokens came between"
	);
}

#[tokio::test]
async fn a_token_that_cannot_be_one_is_refused_without_hashing() {
	let app = app();
	CONFIGURED_HASH_CHECKS.with(|c| c.set(0));
	assert_eq!(
		get(&app, &"x".repeat(5_000), "198.51.100.2").await,
		StatusCode::UNAUTHORIZED
	);
	assert_eq!(
		CONFIGURED_HASH_CHECKS.with(std::cell::Cell::get),
		0,
		"no hash was computed for an oversized token"
	);
}

#[tokio::test]
async fn once_the_configured_token_is_known_a_wrong_one_costs_no_argon2() {
	let app = app();
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.3").await,
		StatusCode::OK
	);
	CONFIGURED_ARGON2_RUNS.with(|c| c.set(0));
	for n in 0..50 {
		assert_eq!(
			get(&app, "wrong", &format!("203.0.113.{n}")).await,
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(CONFIGURED_ARGON2_RUNS.with(std::cell::Cell::get), 0);
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.4").await,
		StatusCode::OK,
		"and the right one still gets in"
	);
}

#[tokio::test]
async fn before_it_is_known_the_wrong_guesses_that_reach_argon2_are_bounded_overall() {
	let app = app();
	CONFIGURED_ARGON2_RUNS.with(|c| c.set(0));
	for n in 0..100 {
		get(&app, "wrong", &format!("203.0.113.{n}")).await;
	}
	let runs = CONFIGURED_ARGON2_RUNS.with(std::cell::Cell::get);
	assert_eq!(
		runs, 60,
		"60 argon2 runs for 100 wrong tokens from 100 clients, no more"
	);
}
