//! Unit tests for the auth-failure limiter.
//!
//! The clock and the window length are passed in by the caller, so these
//! tests drive `now` explicitly and never sleep. Each test is a CONTROL:
//! a fault in the limiter (a flipped comparison, a missing window roll)
//! would surface as a red run before the test reaches its assertion.

use super::limiter::{AUTH_MAX_FAILURES, AuthLimiter, ClientLimiters, MAX_CLIENTS};
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

#[test]
fn the_table_is_bounded_and_the_overflow_is_limited_as_a_group() {
	let mut limiters = ClientLimiters::new(WINDOW);
	let t0 = Instant::now();
	// One failure each from more distinct IPv6 /64s than the table holds.
	for n in 0..(MAX_CLIENTS as u64 + 500) {
		let ip = IpAddr::from(std::net::Ipv6Addr::from((u128::from(n) + 1) << 64));
		limiters.record_failure(Some(ip), t0);
	}
	assert_eq!(limiters.tracked(), MAX_CLIENTS, "memory stays bounded");
	// A client with an entry keeps its own budget.
	assert!(!limiters.is_limited(
		Some(IpAddr::from(std::net::Ipv6Addr::from(1u128 << 64))),
		t0
	));
	// Enough more failures from clients that did not fit exhaust the shared one.
	for n in 0..u64::from(AUTH_MAX_FAILURES) {
		let ip = IpAddr::from(std::net::Ipv6Addr::from((u128::from(n) + 900_000) << 64));
		limiters.record_failure(Some(ip), t0);
	}
	let stranger = IpAddr::from(std::net::Ipv6Addr::from(7_000_000u128 << 64));
	assert!(limiters.is_limited(Some(stranger), t0));
	// Once the window passes the table drains and the stranger is admitted again.
	let later = t0 + WINDOW + Duration::from_secs(2);
	limiters.record_failure(client(9), later);
	assert!(limiters.tracked() < MAX_CLIENTS);
	assert!(!limiters.is_limited(Some(stranger), later));
}
