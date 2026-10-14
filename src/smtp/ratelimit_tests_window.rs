//! The window order, refusal at the cap, and refunds of [`WindowLimiter`].

use super::*;

/// A first charge larger than the cap is refused and charges nothing,
/// after a window restart as well as on a key never seen before.
#[test]
fn a_charge_over_the_cap_is_refused_at_the_start_of_a_window() {
	let limiter = WindowLimiter::new(60);
	assert!(!limiter.check_n("fresh", 11, 10, 1_000));
	assert!(limiter.check_n("fresh", 10, 10, 1_000));
	// A minute later the window restarts; an oversized charge is still
	// refused and leaves the new window empty.
	assert!(!limiter.check_n("fresh", 11, 10, 1_060));
	assert!(limiter.check_n("fresh", 10, 10, 1_060));
}

/// The submission limiter is keyed by authenticated accounts and tenants,
/// a key space the directory bounds. A full map must neither refuse the
/// next account (10 001 accounts sending inside one minute would lock out
/// every account that had not sent yet) nor reset a running window to make
/// room for it.
#[test]
fn the_submission_limiter_admits_every_account_past_the_cap() {
	let limiter = WindowLimiter::for_authenticated_keys(60);
	assert!(limiter.check_n("alice", 5, 5, 1_000));
	for i in 0..MAX_ENTRIES {
		assert!(
			limiter.check(&format!("account{i}"), 5, 1_010),
			"account {} of {} was locked out by the map size",
			i + 2,
			MAX_ENTRIES + 1
		);
	}
	assert!(
		!limiter.check("alice", 5, 1_010),
		"alice's running window must still be full"
	);
	// Once windows are over, new accounts take their slots back: memory
	// stays near the number of accounts sending inside one window.
	for i in 0..MAX_ENTRIES {
		assert!(limiter.check(&format!("later{i}"), 5, 1_100));
	}
	assert!(limiter.len() <= MAX_ENTRIES + 1, "{}", limiter.len());
}

/// The evicting limiter drops the oldest window, not the oldest key: a
/// key that started a new window after the others keeps its count.
#[test]
fn eviction_takes_the_oldest_window_not_the_first_key_inserted() {
	let limiter = WindowLimiter::new(60);
	assert!(limiter.check("alice", 2, 1_000));
	for i in 0..MAX_ENTRIES - 1 {
		assert!(limiter.check(&format!("k{i}"), 2, 1_030));
	}
	// alice's window restarts after every other key was inserted.
	assert!(limiter.check_n("alice", 2, 2, 1_070));
	assert!(limiter.check("late", 2, 1_070));
	assert!(
		!limiter.check("alice", 2, 1_070),
		"alice's running window must survive the eviction"
	);
}

/// `has_room` answers without charging.
#[test]
fn has_room_does_not_charge() {
	let limiter = WindowLimiter::for_authenticated_keys(60);
	for _ in 0..10 {
		assert!(limiter.has_room("alice", 1, 1, 1_000));
	}
	assert!(limiter.check("alice", 1, 1_000));
	assert!(!limiter.has_room("alice", 1, 1, 1_000));
	assert!(limiter.has_room("alice", 1, 1, 1_060), "the window is over");
	assert!(!limiter.has_room("bob", 2, 1, 1_000));
}

/// A refund credits the window that took the charge and nothing else.
#[test]
fn a_refund_credits_only_the_window_that_was_charged() {
	let limiter = WindowLimiter::for_authenticated_keys(60);
	assert!(limiter.check_n("alice", 3, 3, 1_000));
	limiter.refund("alice", 3, 1_000);
	assert!(
		limiter.check_n("alice", 3, 3, 1_001),
		"refunded units fit again"
	);
	// A refund for a charge from an earlier window is dropped.
	assert!(limiter.check_n("alice", 3, 3, 1_070));
	limiter.refund("alice", 3, 1_001);
	assert!(
		!limiter.check("alice", 3, 1_071),
		"a stale refund must not credit the new window"
	);
	// A refund never takes the count below zero.
	limiter.refund("bob", 5, 1_000);
	assert!(!limiter.check_n("bob", 4, 3, 1_000));
}

/// The window queue stays bounded however many windows one key starts.
#[test]
fn window_records_stay_bounded_under_many_restarts() {
	let limiter = WindowLimiter::for_authenticated_keys(60);
	for i in 0..(3 * MAX_ENTRIES as u64) {
		assert!(limiter.check("alice", 1, 1_000 + i * 60));
		assert!(limiter.window_records() <= 2 * MAX_ENTRIES);
	}
}
