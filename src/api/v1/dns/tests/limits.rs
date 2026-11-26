//! The bounds of the routes: how many domains, how many checks at once, how
//! long a check may take.

use std::sync::Arc;

use axum::http::{StatusCode, header};

use super::fixture::*;
use crate::api::ApiState;

fn many(count: usize) -> Vec<String> {
	(0..count).map(|n| format!("d{n}.example")).collect()
}

#[tokio::test]
async fn a_listing_of_too_many_domains_asks_for_one_name() {
	let dns = Arc::new(Recording::default());
	let big = build(&many(201), "", dns.clone(), true);
	let (status, body) = get(&big, "/api/v1/dns/records", token()).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"]["code"], "invalid_input");
	let (status, body) = get(&big, "/api/v1/dns/records?domain=d7.example", token()).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"naming one domain is the way out: {body}"
	);
	let edge = build(&many(200), "", dns, true);
	let (status, body) = get(&edge, "/api/v1/dns/records", token()).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"200 domains is within the limit: {body}"
	);
}

#[tokio::test]
async fn a_check_of_too_many_domains_looks_nothing_up() {
	let dns = Arc::new(Recording::default());
	let big = build(&many(21), "", dns.clone(), true);
	let (status, body) = get(&big, "/api/v1/dns/verify", token()).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert!(dns.names().is_empty(), "{:?}", dns.names());
	let (status, body) = get(&big, "/api/v1/dns/verify?domain=d3.example", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let edge = build(&many(20), "", Arc::new(Recording::default()), true);
	let (status, body) = get(&edge, "/api/v1/dns/verify", token()).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"20 domains is within the limit: {body}"
	);
}

fn spawn_check(state: &ApiState) -> tokio::task::JoinHandle<StatusCode> {
	let state = state.clone();
	tokio::spawn(async move {
		let (status, _, _) = get_with_headers(&state, "/api/v1/dns/verify", Some(token())).await;
		status
	})
}

async fn until_asked(dns: &Recording, at_least: usize) {
	for _ in 0..2000 {
		if dns.names().len() >= at_least {
			return;
		}
		tokio::task::yield_now().await;
		tokio::time::sleep(std::time::Duration::from_millis(1)).await;
	}
	panic!("the checks never started");
}

/// Two checks may run at once and the third is told to come back; when they
/// finish, or are dropped, the places are free again.
#[tokio::test]
async fn only_a_few_checks_run_at_once_and_the_places_come_back() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with("", dns.clone());
	let first = spawn_check(&world.state);
	let second = spawn_check(&world.state);
	until_asked(&dns, 2).await;
	let (status, headers, body) =
		get_with_headers(&world.state, "/api/v1/dns/verify", Some(token())).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert!(
		headers.get(header::RETRY_AFTER).is_some(),
		"a 429 states the wait"
	);
	// The records route needs no place: it makes no lookup.
	let (status, _) = get(&world, "/api/v1/dns/records", token()).await;
	assert_eq!(status, StatusCode::OK);
	// A client that gives up leaves its place.
	first.abort();
	second.abort();
	let _ = (first.await, second.await);
	hold.add_permits(10_000);
	let (status, body) = get(&world, "/api/v1/dns/verify", token()).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"the places were not given back: {body}"
	);
}

/// A resolver that never answers cannot hold a place for ever.
#[tokio::test(start_paused = true)]
async fn a_check_that_never_finishes_is_cut_off() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with("", dns);
	// The test's own limit is far past the route's, so a route that never
	// gives up fails here and does not hang.
	let (status, body) = tokio::time::timeout(
		std::time::Duration::from_secs(3600),
		get(&world, "/api/v1/dns/verify", token()),
	)
	.await
	.expect("the route gave up on its own");
	assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
	assert_eq!(body["error"]["code"], "timeout");
	hold.add_permits(10_000);
	let (status, body) = get(&world, "/api/v1/dns/verify", token()).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"the place was kept after the timeout: {body}"
	);
}
