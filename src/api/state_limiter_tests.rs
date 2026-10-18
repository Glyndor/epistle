//! Unit tests for the auth-failure limiter.
//!
//! The clock and the window length are passed in by the caller, so these
//! tests drive `now` explicitly and never sleep. Each test is a CONTROL:
//! a fault in the limiter (a flipped comparison, a missing window roll)
//! would surface as a red run before the test reaches its assertion.

use super::limiter::{
	AUTH_MAX_FAILURES, AuthLimiter, ClientLimiters, GLOBAL_MAX_FAILURES, MAX_CLIENTS,
	NET_BUDGET_FACTOR,
};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A short window keeps the arithmetic in the tests easy to read and avoids
/// any chance of the system clock advancing meaningfully across the run.
const WINDOW: Duration = Duration::from_secs(60);

fn limiter() -> AuthLimiter {
	AuthLimiter::new(WINDOW, Instant::now())
}

#[test]
fn limiter_blocks_at_the_threshold_within_the_window() {
	let mut l = limiter();
	let t0 = Instant::now();
	for _ in 0..AUTH_MAX_FAILURES {
		l.record_failure(t0);
	}
	assert!(l.is_limited(t0 + Duration::from_secs(1)));
	assert!(l.is_limited(t0 + Duration::from_secs(59)));
}

#[test]
fn limiter_admits_below_the_threshold() {
	let mut l = limiter();
	let t0 = Instant::now();
	for _ in 0..(AUTH_MAX_FAILURES - 1) {
		l.record_failure(t0);
	}
	assert!(!l.is_limited(t0));
}

#[test]
fn limiter_forgets_failures_once_the_window_has_passed() {
	let mut l = limiter();
	let t0 = Instant::now();
	for _ in 0..AUTH_MAX_FAILURES {
		l.record_failure(t0);
	}
	// At `t0 + window` the roll kicks in: the count drops and the limiter
	// is no longer tripped.
	assert!(!l.is_limited(t0 + WINDOW));
	// One more failure inside the new window has not reached the threshold.
	l.record_failure(t0 + WINDOW + Duration::from_secs(1));
	assert!(!l.is_limited(t0 + WINDOW + Duration::from_secs(1)));
}

#[test]
fn limiter_reset_clears_the_count() {
	let mut l = limiter();
	let t0 = Instant::now();
	for _ in 0..AUTH_MAX_FAILURES {
		l.record_failure(t0);
	}
	l.reset(t0);
	assert!(!l.is_limited(t0));
}

#[test]
fn a_failure_after_the_window_starts_a_new_window() {
	let mut l = limiter();
	let t0 = Instant::now();
	for _ in 0..(AUTH_MAX_FAILURES - 1) {
		l.record_failure(t0);
	}
	// One more failure, but past the window end: the 19 prior failures are
	// dropped, and the single new failure is well below the threshold.
	let past = t0 + WINDOW + Duration::from_secs(1);
	l.record_failure(past);
	assert!(!l.is_limited(past));
}

fn client(n: u32) -> Option<IpAddr> {
	Some(IpAddr::from(std::net::Ipv4Addr::from(0xC633_6400 + n)))
}

#[test]
fn one_clients_failures_do_not_limit_another() {
	let mut limiters = ClientLimiters::new(WINDOW);
	let t0 = Instant::now();
	for _ in 0..AUTH_MAX_FAILURES {
		limiters.record_failure(client(1), t0);
	}
	assert!(limiters.is_limited(client(1), t0));
	assert!(!limiters.is_limited(client(2), t0));
}

#[test]
fn a_success_clears_only_its_own_client() {
	let mut limiters = ClientLimiters::new(WINDOW);
	let t0 = Instant::now();
	for _ in 0..AUTH_MAX_FAILURES {
		limiters.record_failure(client(1), t0);
		limiters.record_failure(client(2), t0);
	}
	limiters.reset(client(2));
	assert!(limiters.is_limited(client(1), t0));
	assert!(!limiters.is_limited(client(2), t0));
}

/// The `n`th IPv6 address, each in a /64 and a /48 of its own.
fn far(n: u64) -> Option<IpAddr> {
	Some(IpAddr::from(std::net::Ipv6Addr::from(
		(u128::from(n) + 1) << 80,
	)))
}

/// Address `host` in the /64 number `slash64` of the /48 `net`.
fn in_net(net: u64, slash64: u64, host: u64) -> Option<IpAddr> {
	let bits = (u128::from(net) << 80) | (u128::from(slash64) << 64) | u128::from(host);
	Some(IpAddr::from(std::net::Ipv6Addr::from(bits)))
}

#[test]
fn the_tables_are_bounded_and_a_client_without_an_entry_is_never_limited() {
	let mut limiters = ClientLimiters::new(WINDOW);
	let t0 = Instant::now();
	for n in 0..(MAX_CLIENTS as u64 + 500) {
		limiters.record_failure(far(n), t0);
	}
	assert_eq!(limiters.tracked(), MAX_CLIENTS, "memory stays bounded");
	// A client with an entry keeps its own budget.
	assert!(!limiters.is_limited(far(0), t0));
	// One that never failed and has no room is not held to anyone's budget,
	// however many others failed.
	for n in 0..u64::from(AUTH_MAX_FAILURES) {
		limiters.record_failure(far(900_000 + n), t0);
	}
	assert!(!limiters.is_limited(far(7_000_000), t0));
	// Once the window passes the tables drain.
	let later = t0 + WINDOW + Duration::from_secs(2);
	limiters.record_failure(client(9), later);
	assert!(limiters.tracked() < MAX_CLIENTS);
}

#[test]
fn rotating_through_the_slash_64s_of_one_allocation_is_stopped_by_its_slash_48() {
	let mut limiters = ClientLimiters::new(WINDOW);
	let t0 = Instant::now();
	let each = AUTH_MAX_FAILURES - 1;
	let slash_64s = u64::from(NET_BUDGET_FACTOR);
	// Every /64 stays under its own budget.
	for slash64 in 0..slash_64s {
		for host in 0..each {
			limiters.record_failure(in_net(5, slash64, u64::from(host)), t0);
		}
	}
	assert!(
		!limiters.is_limited(in_net(5, 0, 1), t0),
		"its /64 is under budget"
	);
	// Spending the /48's budget (8 times a client's) limits the rest of it.
	let missing = AUTH_MAX_FAILURES * NET_BUDGET_FACTOR - each * NET_BUDGET_FACTOR;
	for host in 0..missing {
		limiters.record_failure(in_net(5, 1, 100 + u64::from(host)), t0);
	}
	assert!(
		limiters.is_limited(in_net(5, 40, 1), t0),
		"a fresh /64 of that /48"
	);
	assert!(
		!limiters.is_limited(in_net(6, 0, 1), t0),
		"another /48 is untouched"
	);
}

#[test]
fn the_global_ceiling_is_reached_by_failures_and_never_limits_a_client() {
	let mut limiters = ClientLimiters::new(WINDOW);
	let t0 = Instant::now();
	for n in 0..u64::from(GLOBAL_MAX_FAILURES - 1) {
		limiters.record_failure(far(n), t0);
	}
	assert!(!limiters.flood_limited(t0));
	limiters.record_failure(far(999_999), t0);
	assert!(limiters.flood_limited(t0));
	// It only answers the question asked after a failure: a client that has not
	// failed is not limited by it, which is what keeps valid tokens working.
	assert!(!limiters.is_limited(far(5_000_000), t0));
	let later = t0 + WINDOW + Duration::from_secs(2);
	assert!(!limiters.flood_limited(later));
}
