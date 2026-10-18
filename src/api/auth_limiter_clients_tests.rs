//! The bearer-token failure limit is kept per client, so a flood of wrong
//! tokens from one address cannot lock everyone else out of the API, and a
//! success elsewhere cannot give the flooder its budget back.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::time::Duration;
use tower::ServiceExt;

use super::tests::{TOKEN, test_state};
use super::*;

async fn get_status(app: &axum::Router, token: &str, peer: &str) -> StatusCode {
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
	// Keep the directory alive for the whole process: the router borrows files in it.
	let path = dir.keep();
	router(test_state(&path, 0).with_auth_window(Duration::from_secs(3600)))
}

#[tokio::test]
async fn a_flood_of_wrong_tokens_from_one_client_does_not_lock_out_the_others() {
	let app = app();
	for _ in 0..20 {
		assert_eq!(
			get_status(&app, "wrong", "198.51.100.1").await,
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		get_status(&app, "wrong", "198.51.100.1").await,
		StatusCode::TOO_MANY_REQUESTS,
		"the flooding client is limited"
	);
	assert_eq!(
		get_status(&app, TOKEN.as_str(), "203.0.113.9").await,
		StatusCode::OK,
		"a valid token from another client is not"
	);
}

#[tokio::test]
async fn the_limit_applies_before_the_token_is_looked_at() {
	let app = app();
	for _ in 0..20 {
		get_status(&app, "wrong", "198.51.100.1").await;
	}
	// A guess that happens to be right must not get through while the limit
	// holds, or the limit would not slow guessing down.
	assert_eq!(
		get_status(&app, TOKEN.as_str(), "198.51.100.1").await,
		StatusCode::TOO_MANY_REQUESTS
	);
}

#[tokio::test]
async fn a_success_from_another_client_does_not_reset_the_flooders_count() {
	let app = app();
	for _ in 0..19 {
		get_status(&app, "wrong", "198.51.100.1").await;
		assert_eq!(
			get_status(&app, TOKEN.as_str(), "203.0.113.9").await,
			StatusCode::OK
		);
	}
	get_status(&app, "wrong", "198.51.100.1").await;
	assert_eq!(
		get_status(&app, "wrong", "198.51.100.1").await,
		StatusCode::TOO_MANY_REQUESTS,
		"twenty failures from one client stop it however much traffic succeeds around it"
	);
}

#[tokio::test]
async fn an_ipv6_client_is_its_slash_64() {
	let app = app();
	for last in 1..=20 {
		get_status(&app, "wrong", &format!("2001:db8:1:2::{last}")).await;
	}
	assert_eq!(
		get_status(&app, "wrong", "2001:db8:1:2:ffff::1").await,
		StatusCode::TOO_MANY_REQUESTS
	);
	assert_eq!(
		get_status(&app, TOKEN.as_str(), "2001:db8:1:3::1").await,
		StatusCode::OK
	);
}

#[tokio::test]
async fn a_flood_from_many_clients_never_blocks_a_valid_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.keep();
	let app = router(
		test_state(&path, 0)
			.with_auth_window(Duration::from_secs(3600))
			.with_auth_global_max(30),
	);
	// One wrong token from each of thirty different clients.
	for n in 1..=29u32 {
		assert_eq!(
			get_status(&app, "wrong", &format!("10.0.0.{n}")).await,
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		get_status(&app, "wrong", "10.0.0.30").await,
		StatusCode::TOO_MANY_REQUESTS,
		"the failure that passes the ceiling is told to slow down"
	);
	assert_eq!(
		get_status(&app, "wrong", "10.0.1.1").await,
		StatusCode::TOO_MANY_REQUESTS,
		"and so is a client that never failed before"
	);
	assert_eq!(
		get_status(&app, TOKEN.as_str(), "192.0.2.77").await,
		StatusCode::OK,
		"a valid token is not asked about the ceiling"
	);
}

#[tokio::test]
async fn a_valid_token_gets_in_from_an_ipv6_net_whose_budget_is_spent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(&dir.keep(), 0).with_auth_window(Duration::from_secs(3600));
	// Eight /64s of one /48, each spending its own whole budget.
	for slash64 in 0..8 {
		for host in 1..=20 {
			let ip = format!("2001:db8:7:{slash64}::{host}").parse().expect("ip");
			state.seed_auth_failure(ip);
		}
	}
	let app = router(state);
	assert_eq!(
		get_status(&app, "wrong", "2001:db8:7:99::1").await,
		StatusCode::TOO_MANY_REQUESTS,
		"a wrong token from another /64 of that /48 is told to slow down"
	);
	assert_eq!(
		get_status(&app, TOKEN.as_str(), "2001:db8:7:99::2").await,
		StatusCode::OK,
		"a valid one is not asked about the /48's budget"
	);
}
