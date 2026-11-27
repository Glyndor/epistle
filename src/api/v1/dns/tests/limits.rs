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
	spawn_check_as(state, token())
}

fn spawn_check_as(state: &ApiState, secret: &'static str) -> tokio::task::JoinHandle<StatusCode> {
	let state = state.clone();
	tokio::spawn(async move {
		let (status, _, _) = get_with_headers(&state, "/api/v1/dns/verify", Some(secret)).await;
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

/// Wait until the resolver was asked about a name under `domain`.
async fn until_asked_about(dns: &Recording, domain: &str) {
	for _ in 0..2000 {
		if dns.names().iter().any(|name| name.ends_with(domain)) {
			return;
		}
		tokio::task::yield_now().await;
		tokio::time::sleep(std::time::Duration::from_millis(1)).await;
	}
	panic!("nothing was asked about {domain}");
}

/// Wait until the state holds `places` places and `keys` turn keys.
async fn until_taken(state: &ApiState, places: usize, keys: usize) {
	for _ in 0..2000 {
		if state.dns_places_in_progress() == places && state.dns_turn_keys_in_progress() == keys {
			return;
		}
		tokio::task::yield_now().await;
		tokio::time::sleep(std::time::Duration::from_millis(1)).await;
	}
	panic!("the state never held {places} places and {keys} turn keys");
}

/// The places are shared: a tenant holds one at a time, so a tenant that
/// holds one leaves another for the others. The tenant that asks twice is
/// told to come back, and the shared limit still holds for everyone
/// together.
#[tokio::test]
async fn a_second_tenant_verifies_while_the_first_holds_its_place() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with("", dns.clone());
	// The first tenant takes a place and stays on it.
	let first = spawn_check_as(&world.state, CONFINED);
	until_asked_about(&dns, "a.example").await;
	assert_eq!(world.state.dns_places_in_progress(), 1);
	assert_eq!(world.state.dns_turn_keys_in_progress(), 1);
	// The same tenant asking again is told to come back, and told at once: a
	// check the server admitted would sit on the held resolver and this
	// would time out.
	let (status, headers, body) = tokio::time::timeout(
		std::time::Duration::from_secs(10),
		get_with_headers(&world.state, "/api/v1/dns/verify", Some(CONFINED)),
	)
	.await
	.expect("the second check of one tenant was admitted");
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert!(
		headers.get(header::RETRY_AFTER).is_some(),
		"a 429 states the wait"
	);
	// The other tenant reaches the resolver while the first one holds its
	// place: the first tenant cannot keep the others out.
	let second = spawn_check_as(&world.state, CONFINED_B);
	until_asked_about(&dns, "b.example").await;
	assert_eq!(world.state.dns_places_in_progress(), 2);
	assert_eq!(world.state.dns_turn_keys_in_progress(), 2);
	// Both places are taken now: the shared limit holds for everyone
	// together, the operator included.
	let (status, _, body) =
		get_with_headers(&world.state, "/api/v1/dns/verify", Some(READER)).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	first.abort();
	second.abort();
	let _ = (first.await, second.await);
}

/// A key with no tenant of its own is held to the shared limit only, as it
/// was before: it takes a place whenever there is one free.
#[tokio::test]
async fn a_key_without_a_tenant_takes_a_place_whenever_there_is_one() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with("", dns.clone());
	let first = spawn_check_as(&world.state, READER);
	let second = spawn_check_as(&world.state, READER);
	// Both places are taken and no tenant holds one: the key that reaches
	// every domain is held to the shared limit and to nothing else.
	until_taken(&world.state, 2, 0).await;
	let (status, headers, body) =
		get_with_headers(&world.state, "/api/v1/dns/verify", Some(READER)).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert!(
		headers.get(header::RETRY_AFTER).is_some(),
		"a 429 states the wait"
	);
	first.abort();
	second.abort();
	let _ = (first.await, second.await);
}

/// A request that gives up leaves its place and its turn: the tenant may
/// check again and the shared places are whole again.
#[tokio::test]
async fn the_place_is_given_back_when_the_request_is_cancelled() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with("", dns.clone());
	let first = spawn_check_as(&world.state, CONFINED);
	until_asked_about(&dns, "a.example").await;
	assert_eq!(world.state.dns_places_in_progress(), 1);
	assert_eq!(world.state.dns_turn_keys_in_progress(), 1);
	// The client gives up: the check is dropped, and with it the place and
	// the turn it held.
	first.abort();
	let _ = first.await;
	assert_eq!(
		world.state.dns_places_in_progress(),
		0,
		"the place was kept after the cancellation"
	);
	assert_eq!(
		world.state.dns_turn_keys_in_progress(),
		0,
		"the turn was kept after the cancellation"
	);
	// The tenant checks again and the operator takes the other place: both
	// places are taken again, so the cancelled one gave its place back.
	let again = spawn_check_as(&world.state, CONFINED);
	let operator = spawn_check_as(&world.state, READER);
	until_taken(&world.state, 2, 1).await;
	let (status, _, body) = tokio::time::timeout(
		std::time::Duration::from_secs(10),
		get_with_headers(&world.state, "/api/v1/dns/verify", Some(READER)),
	)
	.await
	.expect("a check was admitted with both places taken");
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	again.abort();
	operator.abort();
	let _ = (again.await, operator.await);
}

/// Without a configured tenant, the domain itself is the turn: two keys that
/// reach the same domain share one turn, so the second is told to come back.
#[tokio::test]
async fn two_keys_of_one_domain_share_its_turn() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with("", dns.clone());
	let mut keys = crate::api::ApiKeyStore::open(world.state.data_dir()).expect("key store");
	keys.add(crate::api::api_keys::ApiKey {
		grants: Vec::new(),
		label: "confined-again".to_string(),
		hash: crate::api::api_keys::sha256_hash("dns-confined-again-secret"),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string()],
		domains: vec!["a.example".to_string()],
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
	let text = std::fs::read_to_string(world.state.data_dir().join("api_keys.toml")).expect("keys");
	world.state.api_keys().reload_from(&text).expect("reload");
	let first = spawn_check_as(&world.state, CONFINED);
	until_asked_about(&dns, "a.example").await;
	let (status, _, body) = tokio::time::timeout(
		std::time::Duration::from_secs(10),
		get_with_headers(
			&world.state,
			"/api/v1/dns/verify",
			Some("dns-confined-again-secret"),
		),
	)
	.await
	.expect("a second key of one domain was admitted");
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	first.abort();
	let _ = first.await;
}

/// The turn belongs to the tenant, not to the domains the key names: two
/// keys of one tenant that name different domains share the turn, so they
/// cannot take the two places between them. A key of another tenant is not
/// held back by it.
#[tokio::test]
async fn two_keys_of_one_tenant_share_its_turn() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with_tenants(
		&[
			("one", &["a.example", "b.example"]),
			("two", &["c.example"]),
		],
		dns.clone(),
	);
	// The first key takes the turn of its tenant and stays on it.
	let first = spawn_check_as(&world.state, CONFINED);
	until_asked_about(&dns, "a.example").await;
	assert_eq!(world.state.dns_places_in_progress(), 1);
	assert_eq!(world.state.dns_turn_keys_in_progress(), 1);
	// The other key of the same tenant, naming another of its domains, is
	// told to come back: the two places are not one tenant's to take.
	let (status, headers, body) = tokio::time::timeout(
		std::time::Duration::from_secs(10),
		get_with_headers(&world.state, "/api/v1/dns/verify", Some(CONFINED_B)),
	)
	.await
	.expect("the second key of one tenant was admitted");
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert!(
		headers.get(header::RETRY_AFTER).is_some(),
		"a 429 states the wait"
	);
	// A key of another tenant reaches the resolver while the first one holds
	// its place: the first tenant cannot keep the others out.
	let second = spawn_check_as(&world.state, CONFINED_C);
	until_asked_about(&dns, "c.example").await;
	assert_eq!(world.state.dns_places_in_progress(), 2);
	assert_eq!(world.state.dns_turn_keys_in_progress(), 2);
	first.abort();
	second.abort();
	let _ = (first.await, second.await);
}

/// A key that reaches one domain of each of two tenants holds both turns:
/// it keeps the other keys of both tenants out while it runs, and gives
/// both turns back when it ends.
#[tokio::test]
async fn a_key_of_two_tenants_holds_both_turns() {
	let hold = Arc::new(tokio::sync::Semaphore::new(0));
	let dns = Arc::new(Recording {
		hold: Some(hold.clone()),
		..Default::default()
	});
	let world = world_with_tenants(
		&[("one", &["a.example"]), ("two", &["c.example"])],
		dns.clone(),
	);
	// The key of both tenants takes both turns at once, before it asks the
	// resolver anything.
	let first = spawn_check_as(&world.state, ACROSS);
	until_taken(&world.state, 1, 2).await;
	// The other key of each tenant is told to come back.
	for secret in [CONFINED, CONFINED_C] {
		let (status, headers, body) = tokio::time::timeout(
			std::time::Duration::from_secs(10),
			get_with_headers(&world.state, "/api/v1/dns/verify", Some(secret)),
		)
		.await
		.expect("a key of a busy tenant was admitted");
		assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
		assert!(
			headers.get(header::RETRY_AFTER).is_some(),
			"a 429 states the wait"
		);
	}
	// The check ends, and both turns are free again.
	hold.add_permits(10_000);
	let status = first.await.expect("the check");
	assert_eq!(status, StatusCode::OK);
	assert!(
		dns.names().iter().any(|name| name.ends_with("c.example")),
		"the check never reached the domain of the second tenant: {:?}",
		dns.names()
	);
	assert_eq!(
		world.state.dns_turn_keys_in_progress(),
		0,
		"a turn was kept after the check ended"
	);
	// A key of each tenant checks again.
	for secret in [CONFINED, CONFINED_C] {
		let (status, body) = get(&world, "/api/v1/dns/verify", secret).await;
		assert_eq!(status, StatusCode::OK, "{body}");
	}
}
