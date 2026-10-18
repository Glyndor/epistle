//! What a wrong bearer token costs, and what a right one cannot undo: guesses
//! are bounded per client and a valid call does not give the budget back, a
//! malformed token is refused before any hashing, and the legacy argon2 check
//! of the configured token is not a free CPU burner.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::time::Duration;
use tower::ServiceExt;

use super::state::CONFIGURED_HASH_CHECKS;
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
	app_and_state().0
}

fn app_and_state() -> (axum::Router, ApiState) {
	app_with_queue(64)
}

fn app_with_queue(queue: usize) -> (axum::Router, ApiState) {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(&dir.keep(), 0)
		.with_auth_window(Duration::from_secs(3600))
		.with_argon2_queue(queue);
	(router(state.clone()), state)
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
	let (app, state) = app_and_state();
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.3").await,
		StatusCode::OK
	);
	let (before, _) = state.argon2_stats();
	for n in 0..50 {
		assert_eq!(
			get(&app, "wrong", &format!("203.0.113.{n}")).await,
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		state.argon2_stats().0,
		before,
		"no argon2 for a wrong bearer"
	);
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.4").await,
		StatusCode::OK,
		"and the right one still gets in"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_guesses_never_run_more_argon2_than_the_gate_allows() {
	let (app, state) = app_with_queue(4);
	// Four wrong tokens from four clients at the same moment (the whole queue), before the
	// real token has ever been seen: each would need an argon2.
	let calls: Vec<_> = (0..4)
		.map(|n| {
			let app = app.clone();
			tokio::spawn(async move { get(&app, "wrong", &format!("203.0.113.{n}")).await })
		})
		.collect();
	for call in calls {
		assert_eq!(call.await.expect("task"), StatusCode::UNAUTHORIZED);
	}
	let (runs, peak) = state.argon2_stats();
	assert_eq!(runs, 4, "every guess is still answered");
	assert!(peak <= 2, "{peak} argon2 verifications at once");
	assert!(peak >= 1);
}

#[tokio::test]
async fn the_operator_gets_in_after_attackers_have_spent_every_budget() {
	let app = app();
	for n in 0..30 {
		get(&app, "wrong", &format!("203.0.113.{n}")).await;
	}
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.8").await,
		StatusCode::OK,
		"the real token is never refused because of other people's guesses"
	);
}

/// Start a wrong-token request from `n` and return its handle.
fn guess(app: &axum::Router, peer: String) -> tokio::task::JoinHandle<StatusCode> {
	let app = app.clone();
	tokio::spawn(async move { get(&app, "wrong", &peer).await })
}

/// Wait until no argon2 is running.
async fn idle(state: &ApiState) {
	for _ in 0..600 {
		if state.argon2_running() == 0 {
			return;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	panic!("argon2 still running");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hanging_up_does_not_free_a_turn_while_its_argon2_still_runs() {
	let (app, state) = app_with_queue(4);
	let first: Vec<_> = (0..4)
		.map(|n| guess(&app, format!("203.0.113.{n}")))
		.collect();
	tokio::time::sleep(Duration::from_millis(150)).await;
	for call in &first {
		call.abort();
	}
	// The next wave arrives while the first one's argon2 are still running.
	let second: Vec<_> = (10..14)
		.map(|n| guess(&app, format!("203.0.113.{n}")))
		.collect();
	for call in second {
		call.await.ok();
	}
	idle(&state).await;
	assert!(
		state.argon2_stats().1 <= 2,
		"{} argon2 at once",
		state.argon2_stats().1
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_arriving_together_from_one_client_cannot_pass_its_budget() {
	let (app, state) = app_and_state();
	// Forty at the same moment from one client, before any is counted: with
	// the budget checked first and charged afterwards all forty would be
	// evaluated. Only the queue's worth are let in at all here, the rest are
	// refused at once, and none of them is evaluated past the budget of 20.
	let calls: Vec<_> = (0..40)
		.map(|_| guess(&app, "203.0.113.50".to_string()))
		.collect();
	let mut statuses = Vec::new();
	for call in calls {
		statuses.push(call.await.expect("task"));
	}
	idle(&state).await;
	assert!(
		state.argon2_stats().0 <= 20,
		"{} evaluations",
		state.argon2_stats().0
	);
	assert!(
		statuses
			.iter()
			.filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
			.count() >= 20
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_queue_refuses_the_next_guess_instead_of_growing() {
	let (app, state) = app_with_queue(4);
	let calls: Vec<_> = (0..12)
		.map(|n| guess(&app, format!("203.0.113.{}", 100 + n)))
		.collect();
	let mut busy = 0;
	for call in calls {
		if call.await.expect("task") == StatusCode::TOO_MANY_REQUESTS {
			busy += 1;
		}
	}
	idle(&state).await;
	assert!(busy >= 6, "{busy} refused of 12 with room for 4");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_operator_gets_in_while_attackers_are_queued() {
	let (app, state) = app_with_queue(4);
	let attackers: Vec<_> = (0..3)
		.map(|n| guess(&app, format!("203.0.113.{}", 150 + n)))
		.collect();
	tokio::time::sleep(Duration::from_millis(50)).await;
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.40").await,
		StatusCode::OK,
		"the real token waits its turn behind the guesses and is accepted"
	);
	for call in attackers {
		call.await.ok();
	}
	idle(&state).await;
}

#[tokio::test]
async fn being_told_the_queue_is_full_is_not_a_failed_credential() {
	let (app, state) = app_with_queue(0);
	// Thirty refusals because there is no room: more than the 20 a client may
	// fail. None checked anything, so none may have been counted.
	for _ in 0..30 {
		assert_eq!(
			get(&app, "wrong", "198.51.100.90").await,
			StatusCode::TOO_MANY_REQUESTS
		);
	}
	// Room is back (the real token is known, so a wrong one is rejected by
	// digest): the client is still where it was, not limited.
	state.prime_configured_token(TOKEN.as_str());
	assert_eq!(
		get(&app, "wrong", "198.51.100.90").await,
		StatusCode::UNAUTHORIZED
	);
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.90").await,
		StatusCode::OK
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_guess_gives_its_place_in_the_queue_back() {
	// A queue of two and six guesses one after another, each from a client of
	// its own: if a finished guess kept its place, the third would find the
	// queue full, and with the real 64 the operator would be refused for good
	// after 64 wrong tokens.
	let (app, state) = app_with_queue(2);
	for n in 0..6 {
		assert_eq!(
			get(&app, "wrong", &format!("203.0.113.{}", 30 + n)).await,
			StatusCode::UNAUTHORIZED,
			"guess {n} must not find the queue full"
		);
	}
	assert_eq!(state.argon2_waiting(), 0);
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.9").await,
		StatusCode::OK
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_requests_give_their_places_back_too() {
	let (app, state) = app_with_queue(8);
	let calls: Vec<_> = (0..6)
		.map(|n| guess(&app, format!("203.0.113.{}", 60 + n)))
		.collect();
	tokio::time::sleep(Duration::from_millis(100)).await;
	for call in &calls {
		call.abort();
	}
	for call in calls {
		call.await.ok();
	}
	idle(&state).await;
	assert_eq!(state.argon2_waiting(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_client_cannot_fill_the_queue_alone() {
	let (app, state) = app_and_state();
	// Six at once from one address, with 64 places in the queue.
	let calls: Vec<_> = (0..6)
		.map(|_| guess(&app, "203.0.113.200".to_string()))
		.collect();
	let mut busy = 0;
	for call in calls {
		if call.await.expect("task") == StatusCode::TOO_MANY_REQUESTS {
			busy += 1;
		}
	}
	idle(&state).await;
	assert_eq!(state.argon2_stats().0, 2, "a client holds two places");
	assert_eq!(busy, 4);
	// Someone else is not held back by it.
	assert_eq!(
		get(&app, TOKEN.as_str(), "198.51.100.77").await,
		StatusCode::OK
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_ipv6_allocation_cannot_fill_the_queue_either() {
	let (app, state) = app_and_state();
	// Ten different /64s of one /48 at once.
	let calls: Vec<_> = (0..10)
		.map(|n| guess(&app, format!("2001:db8:77:{n:x}::1")))
		.collect();
	for call in calls {
		call.await.ok();
	}
	idle(&state).await;
	assert_eq!(state.argon2_stats().0, 4, "a /48 holds four places");
}
