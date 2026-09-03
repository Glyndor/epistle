//! Unit tests for the auth-failure limiter.
//!
//! The clock and the window length are passed in by the caller, so these
//! tests drive `now` explicitly and never sleep. Each test is a CONTROL:
//! a fault in the limiter (a flipped comparison, a missing window roll)
//! would surface as a red run before the test reaches its assertion.

use super::*;
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
