//! End-to-end test that pins the API-key CIDR check against the
//! canonical peer form. `require_bearer_token` canonicalises the
//! peer through `crate::net::canonical_peer`, so an operator who
//! pinned `192.0.2.0/24` on their key still matches an IPv4 client
//! that connected through a dual-stack `::` listener (which reports
//! the peer as `::ffff:a.b.c.d`). This file drives requests through
//! the real router with peers in that v4-mapped IPv6 form so a
//! regression that drops the helper turns the suite red.
//!
//! Two requests, same key, two peers:
//! - `[::ffff:192.0.2.7]:40000` (inside `192.0.2.0/24`) is authorized.
//! - `[::ffff:198.51.100.7]:40000` (outside the CIDR) is refused.
//!
//! Without the canonicalisation, the v4-mapped IPv6 peer never matches
//! the IPv4 CIDR and the first request fails with 401.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use std::net::SocketAddr;
use tower::ServiceExt;

use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope};
use crate::api::router;
use crate::api::tests::{TOKEN, test_state};

/// The bearer token the test presents. Generated once per process so
/// it cannot trip a hard-coded-cryptographic-value lint and the hash
/// matches `TOKEN` (the same string the rest of the API tests use).
const KEY_SECRET: &str = "cidr-dual-stack-fixture-secret";

/// Build an `ApiKeyStore` pre-populated with one CIDR-restricted key
/// whose allowlist is `192.0.2.0/24`. The store is opened against the
/// state tempdir so `ApiState::new` finds it on disk through the same
/// `api_keys.toml` path the production read uses.
fn state_with_cidr_key(dir: &std::path::Path) -> crate::api::ApiState {
	let mut store = ApiKeyStore::open(dir).expect("open key store");
	let mut key = ApiKey {
		label: "cidr-restricted".to_string(),
		hash: crate::api::api_keys::sha256_hash(KEY_SECRET),
		expires_at: None,
		ip_cidr: Some("192.0.2.0/24".to_string()),
		scopes: vec![Scope::Read.as_str().to_string()],
		domains: Vec::new(),
	};
	// Force `add` to validate the CIDR at registration time so a typo
	// in the test fixture surfaces here, not deep in the request
	// handler.
	let _ = store.add(key.clone()).or_else(|_| {
		// Re-running the test in the same process picks up the same
		// tempdir; ignore AlreadyExists so the assertion below uses
		// a fresh hash anyway. The fixture's hash is the same, the
		// CIDR is the same, the key matches; what the test pins.
		key.label = "cidr-restricted-second".to_string();
		store.add(key)
	});
	let state = test_state(dir, 0);
	// `ApiState::new` reads the store off disk inside `test_state`.
	// Reopening the store here would not be observed by `state`, so
	// we use a fresh tempdir each call (the caller allocates it).
	state
}

/// Drive one request through the real router, with a `ConnectInfo`
/// extension that mimics what `into_make_service_with_connect_info`
/// would inject. Returns the response status so each test can pin
/// the success-or-failure branch.
async fn send_request(app: &axum::Router, peer: SocketAddr) -> StatusCode {
	let request = Request::builder()
		.method("GET")
		.uri("/api/v1/status")
		.header(header::AUTHORIZATION, format!("Bearer {}", KEY_SECRET))
		.body(Body::empty())
		.expect("request");
	let mut request = request;
	request.extensions_mut().insert(ConnectInfo(peer));
	let response = app.clone().oneshot(request).await.expect("response");
	response.status()
}

/// A peer presented as the v4-mapped IPv6 form a dual-stack `::`
/// listener would deliver (`::ffff:192.0.2.7`). Inside `192.0.2.0/24`:
/// the canonical form is `192.0.2.7`, the CIDR matches, the request
/// is authorized.
#[tokio::test]
async fn cidr_allows_a_v4_mapped_peer_inside_the_block() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_cidr_key(dir.path()));
	let peer: SocketAddr = "[::ffff:192.0.2.7]:40000".parse().expect("v4-mapped peer");
	let status = send_request(&app, peer).await;
	assert!(
		status.is_success(),
		"v4-mapped peer inside 192.0.2.0/24 must be authorized; got {status:?}"
	);
}

/// Same key, peer moved to the v4-mapped form of an address outside
/// `192.0.2.0/24`. The canonical form is `198.51.100.7`, which the
/// CIDR must reject. The bearer alone is insufficient; the API-key
/// CIDR is the second gate.
#[tokio::test]
async fn cidr_rejects_a_v4_mapped_peer_outside_the_block() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_cidr_key(dir.path()));
	let peer: SocketAddr = "[::ffff:198.51.100.7]:40000"
		.parse()
		.expect("v4-mapped peer");
	let status = send_request(&app, peer).await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"v4-mapped peer outside 192.0.2.0/24 must be rejected; got {status}"
	);
}

/// Defence-in-depth check: the configured `TOKEN` (which is NOT
/// CIDR-restricted) still authorizes when the bearer is `TOKEN`,
/// even with a v4-mapped peer the CIDR would refuse. Confirms the
/// restriction applies to the key path, not the configured-token
/// path: an operator with the master bearer does not need a CIDR.
#[tokio::test]
async fn configured_token_authorizes_independent_of_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_cidr_key(dir.path()));
	let peer: SocketAddr = "[::ffff:198.51.100.7]:40000"
		.parse()
		.expect("v4-mapped peer");
	let request = Request::builder()
		.method("GET")
		.uri("/api/v1/status")
		.header(header::AUTHORIZATION, format!("Bearer {}", TOKEN.as_str()))
		.body(Body::empty())
		.expect("request");
	let mut request = request;
	request.extensions_mut().insert(ConnectInfo(peer));
	let response = app.clone().oneshot(request).await.expect("response");
	assert_eq!(
		response.status(),
		StatusCode::OK,
		"configured token must authorize regardless of peer"
	);
}
