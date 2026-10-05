use super::*;

#[test]
fn allows_up_to_the_limit_then_blocks() {
	let limiter = WindowLimiter::new(60);
	assert!(limiter.check("alice", 3, 100));
	assert!(limiter.check("alice", 3, 101));
	assert!(limiter.check("alice", 3, 102));
	// Fourth in the window is blocked.
	assert!(!limiter.check("alice", 3, 103));
}

#[test]
fn window_resets_after_elapsing() {
	let limiter = WindowLimiter::new(60);
	assert!(limiter.check("alice", 2, 100));
	assert!(limiter.check("alice", 2, 110));
	assert!(!limiter.check("alice", 2, 120));
	// A new window (>= 60s after the start) resets the count.
	assert!(limiter.check("alice", 2, 160));
}

#[test]
fn keys_are_independent_and_case_insensitive() {
	let limiter = WindowLimiter::new(60);
	assert!(limiter.check("alice@example.org", 1, 100));
	assert!(!limiter.check("ALICE@example.org", 1, 100));
	// A different key has its own budget.
	assert!(limiter.check("bob@example.org", 1, 100));
}

#[test]
fn zero_limit_is_treated_as_unlimited() {
	// The policy layer is expected to skip the call when the resolved limit
	// is "no limit"; a literal 0 here is the operator's deliberate choice
	// and must not block the message.
	let limiter = WindowLimiter::new(60);
	assert!(limiter.check("alice", 0, 100));
	assert!(limiter.check("alice", 0, 200));
}

#[test]
fn limit_can_change_between_calls() {
	// The policy can raise or lower a limit at any time (e.g. config reload).
	// The window count is per key, not per limit, so a tighter limit
	// immediately enforces against the existing count.
	let limiter = WindowLimiter::new(60);
	assert!(limiter.check("alice", 5, 100));
	assert!(limiter.check("alice", 5, 101));
	// Operator tightens the policy to 1; the existing count of 2 is now over.
	assert!(!limiter.check("alice", 1, 102));
	// Operator relaxes to 100; the next send fits in the same window.
	assert!(limiter.check("alice", 100, 103));
}

#[test]
fn entries_are_evicted_once_stale_and_the_map_stays_bounded() {
	let limiter = WindowLimiter::new(60);
	// Insert 10_001 distinct keys at the same timestamp with a ceiling the
	// limiter never reaches: every check must therefore increment the count
	// and grow the map.
	for i in 0..10_001 {
		assert!(limiter.check(&format!("k{i}"), u32::MAX, 1_000));
	}
	// Sanity: the map has actually accumulated entries.
	assert!(limiter.len() >= 10_001);
	// Three full windows later the existing keys are stale (window start
	// 1_000, now 1_180, gap 180 > 2 * 60 = 120). The check inserts "trigger"
	// and the eviction sweep removes every prior entry.
	assert!(limiter.check("trigger", u32::MAX, 1_000 + 3 * 60));
	let len = limiter.len();
	assert!(len < 10, "stale entries were not evicted: {len}");
}

#[test]
fn a_stale_entry_is_reset_before_counting() {
	// After a limit is reached the entry sits at (start, limit) until the
	// window elapses. A check arriving later than the window must observe a
	// zeroed count, not the residue: a fresh budget applies.
	let limiter = WindowLimiter::new(60);
	let t0 = 100;
	// Burn the entire budget at t0.
	assert!(limiter.check("alice", 2, t0));
	assert!(limiter.check("alice", 2, t0));
	assert!(!limiter.check("alice", 2, t0));
	// At t0 + 120 the window start (100) is stale: the count must reset to
	// zero before the new check is charged.
	assert!(limiter.check("alice", 2, t0 + 120));
	// The next check is still inside the (new) window at 100 + 120: the count
	// is now 1, so the second entry fits but the third does not.
	assert!(limiter.check("alice", 2, t0 + 130));
	assert!(!limiter.check("alice", 2, t0 + 140));
}
