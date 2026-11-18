//! `[api.limiter]` reaches the bearer limiter and the argon2 gate.

use super::super::limiter::{
	AUTH_MAX_FAILURES, AUTH_WINDOW, ClientLimiters, GLOBAL_MAX_FAILURES, NET_BUDGET_FACTOR,
};
use super::*;
use std::net::IpAddr;
use std::time::Instant;

fn limits(text: &str) -> crate::config::ApiLimiter {
	let limits: crate::config::ApiLimiter = toml::from_str(text).expect("parse");
	limits.validate().expect("valid");
	limits
}

fn client(n: u32) -> Option<IpAddr> {
	Some(IpAddr::from(std::net::Ipv4Addr::from(0xC633_6400 + n)))
}

fn in_net(slash64: u64, host: u64) -> Option<IpAddr> {
	let bits = (5u128 << 80) | (u128::from(slash64) << 64) | u128::from(host);
	Some(IpAddr::from(std::net::Ipv6Addr::from(bits)))
}

#[test]
fn the_client_budget_is_the_configured_one() {
	let mut limiters = ClientLimiters::from_config(&limits("max_failures = 3\n"));
	let now = Instant::now();
	for _ in 0..2 {
		limiters.record_failure(client(1), now);
	}
	assert!(!limiters.is_limited(client(1), now), "two of three");
	limiters.record_failure(client(1), now);
	assert!(limiters.is_limited(client(1), now), "three of three");
	assert!(!limiters.is_limited(client(2), now));
}

#[test]
fn the_window_is_the_configured_one() {
	let mut limiters =
		ClientLimiters::from_config(&limits("max_failures = 1\nwindow_secs = 120\n"));
	let now = Instant::now();
	limiters.record_failure(client(1), now);
	assert!(limiters.is_limited(client(1), now + std::time::Duration::from_secs(119)));
	assert!(!limiters.is_limited(client(1), now + std::time::Duration::from_secs(121)));
}

#[test]
fn the_slash_48_budget_is_the_client_budget_times_the_configured_factor() {
	let mut limiters =
		ClientLimiters::from_config(&limits("max_failures = 2\nnetwork_factor = 3\n"));
	let now = Instant::now();
	// Two failures in each of five /64s: ten of the sixth that the /48 allows.
	for slash64 in 0..3 {
		for host in 0..2 {
			limiters.record_failure(in_net(slash64, host), now);
		}
	}
	assert!(
		limiters.limited_after_failure(in_net(40, 1), now),
		"six failures spend a budget of 2 x 3"
	);
	let mut fewer = ClientLimiters::from_config(&limits("max_failures = 2\nnetwork_factor = 3\n"));
	for slash64 in 0..2 {
		for host in 0..2 {
			fewer.record_failure(in_net(slash64, host), now);
		}
	}
	assert!(
		!fewer.limited_after_failure(in_net(40, 1), now),
		"four are not enough"
	);
}

#[test]
fn the_global_ceiling_is_the_configured_one() {
	let mut limiters = ClientLimiters::from_config(&limits("global_max_failures = 100\n"));
	let now = Instant::now();
	for n in 0..99u32 {
		limiters.record_failure(client(n), now);
	}
	assert!(!limiters.limited_after_failure(client(500), now));
	limiters.record_failure(client(200), now);
	assert!(limiters.limited_after_failure(client(500), now));
}

#[tokio::test]
async fn the_argon2_gate_has_the_configured_size() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".into()],
			Default::default(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = ApiState::new_with_optional_token(
		None,
		dir.path().into(),
		vec!["example.org".into()],
		store,
		crate::storage::FsSpool::open(dir.path()).expect("spool"),
	);
	assert_eq!(state.inner.argon2_gate.available_permits(), 2);
	assert_eq!(state.inner.argon2_queue_max, 64);
	let state = state.with_auth_limits(&limits("max_concurrent_hashes = 5\nhash_queue = 7\n"));
	assert_eq!(state.inner.argon2_gate.available_permits(), 5);
	assert_eq!(state.inner.argon2_queue_max, 7);
}

#[test]
fn the_defaults_of_the_section_are_the_values_the_limiter_was_built_with() {
	let defaults = crate::config::ApiLimiter::default();
	assert_eq!(defaults.max_failures(), AUTH_MAX_FAILURES);
	assert_eq!(defaults.window_secs(), AUTH_WINDOW.as_secs());
	assert_eq!(defaults.network_factor(), NET_BUDGET_FACTOR);
	assert_eq!(defaults.global_max_failures(), GLOBAL_MAX_FAILURES);
	assert_eq!(
		defaults.max_concurrent_hashes(),
		super::super::MAX_CONCURRENT_ARGON2
	);
	assert_eq!(defaults.hash_queue(), super::super::MAX_ARGON2_QUEUE);
}
