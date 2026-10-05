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
fn the_map_refuses_unseen_keys_once_the_cap_is_full() {
	// Filling the cap with 10_000 distinct senders, then trying to admit an
	// 11th unseen key inside the same window: the cap is hard, the live
	// entries are not stale, and the unseen key must be refused. The old
	// code let the map grow past EVICTION_THRESHOLD because fresh entries
	// survived the sweep; the new contract refuses them instead.
	let limiter = WindowLimiter::new(60);
	for i in 0..MAX_ENTRIES {
		assert!(
			limiter.check(&format!("k{i}"), u32::MAX, 1_000),
			"the {i}-th distinct key must be admitted below the cap"
		);
	}
	assert_eq!(limiter.len(), MAX_ENTRIES, "the cap should be full");
	// The next unseen key is refused because the incremental pass finds no
	// stale entries inside the same window.
	assert!(
		!limiter.check("overflow", u32::MAX, 1_000),
		"an unseen key at the cap must be refused"
	);
	// The cap is still 10_000: the refusal did not push the map past it.
	assert_eq!(
		limiter.len(),
		MAX_ENTRIES,
		"the cap must not grow past MAX_ENTRIES"
	);
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

#[test]
fn an_active_key_keeps_its_budget_when_the_map_is_full() {
	// The cap is enforced on unseen keys only: a sender that already
	// occupies an entry keeps its budget through every call, even after
	// other senders have pushed the map to the cap. The new check must
	// observe the same per-window count as it would on an empty map.
	let limiter = WindowLimiter::new(60);
	// Establish alice's budget: two events in the window.
	assert!(limiter.check("alice", 2, 1_000));
	assert!(limiter.check("alice", 2, 1_000));
	assert!(
		!limiter.check("alice", 2, 1_000),
		"third event must be blocked"
	);
	// Fill the cap with other senders, still inside alice's window. Alice
	// already occupies one slot, so we admit MAX_ENTRIES - 1 peers.
	for i in 0..MAX_ENTRIES - 1 {
		assert!(limiter.check(&format!("k{i}"), u32::MAX, 1_000));
	}
	assert_eq!(limiter.len(), MAX_ENTRIES, "the cap should be full");
	// alice is still tracked: her third event is blocked (budget = 2),
	// and the cap did not drop her entry.
	assert!(
		!limiter.check("alice", 2, 1_000),
		"active key must keep its budget when the map is full"
	);
	// Window resets: alice's stale entry is reset to count 0, so the next
	// call is admitted. Other senders' stale entries would be reaped by the
	// incremental pass on an unseen-key call, but the active path here
	// only touches alice.
	assert!(limiter.check("alice", 2, 1_000 + 120));
}

#[test]
fn incremental_expiry_admits_new_keys_once_entries_go_stale() {
	// Stale entries (> 2 windows old) are dropped one budget at a time by
	// the incremental pass. After enough passes the cap frees up and the
	// new key is admitted without ever scanning the whole map in a single
	// call.
	let limiter = WindowLimiter::new(60);
	for i in 0..MAX_ENTRIES {
		assert!(limiter.check(&format!("k{i}"), u32::MAX, 1_000));
	}
	// Same window: the unseen key is refused.
	assert!(!limiter.check("late", u32::MAX, 1_000));
	// Two windows later every prior entry is stale (start = 1_000, cutoff
	// = 1_000 + 120 - 120 = 1_000). One incremental pass frees at most
	// EVICTION_SCAN_BUDGET slots, so the first new key after the gap may
	// still be refused; a handful of passes are enough to drain 10_000
	// stale entries through the budget.
	for pass in 0..(MAX_ENTRIES / EVICTION_SCAN_BUDGET + 4) {
		if limiter.check(&format!("late{pass}"), u32::MAX, 1_000 + 120) {
			return;
		}
	}
	panic!("incremental expiry never admitted a new key after the window expired");
}

#[test]
fn scan_count_grows_at_most_linearly_under_thousands_of_distinct_senders() {
	// Regression for #968: each call must do a bounded amount of work even
	// when the map sits at the cap. The scan counter is the number of map
	// entries the incremental expiry pass touched; it must stay linear in
	// the number of `check` calls, not in the map size.
	let limiter = WindowLimiter::new(60);
	// Fill the cap with fresh entries so every subsequent unseen-key call
	// runs the incremental expiry pass.
	for i in 0..MAX_ENTRIES {
		limiter.check(&format!("k{i}"), u32::MAX, 1_000);
	}
	let baseline = limiter.scan_count();
	// Run two batches of unseen-key checks against the saturated map. The
	// incremental pass scans at most EVICTION_SCAN_BUDGET entries per call,
	// so doubling the batch size must at most double the scan counter.
	let n1: usize = 500;
	for i in 0..n1 {
		limiter.check(&format!("flood-a-{i}"), u32::MAX, 1_000);
	}
	let scans_after_n1 = limiter.scan_count() - baseline;
	let n2: usize = 1_000;
	for i in 0..n2 {
		limiter.check(&format!("flood-b-{i}"), u32::MAX, 1_000);
	}
	let scans_after_n2 = limiter.scan_count() - baseline - scans_after_n1;
	// Linear bound: count(2N) is at most 2 * count(N) plus a fixed slack
	// for the per-call overhead that does not depend on the input size.
	// The old code scanned the whole map per sweep, so count(2N) / count(N)
	// was the map size, not 1.
	assert!(
		scans_after_n2 as u128 <= scans_after_n1 as u128 * 2 + 256,
		"scan count grew superlinearly: n1={n1} -> {scans_after_n1}, \
		 n2={n2} -> {scans_after_n2}"
	);
	// Absolute per-call cap: the incremental pass touches at most
	// EVICTION_SCAN_BUDGET entries per call, so even a flooded map cannot
	// exceed two budgets of work per call.
	let per_call_cap = (n2 as u64) * (EVICTION_SCAN_BUDGET as u64) * 2;
	assert!(
		scans_after_n2 <= per_call_cap,
		"per-call scan budget exceeded: n2={n2} -> {scans_after_n2}, cap={per_call_cap}"
	);
}

#[test]
fn map_size_never_exceeds_the_cap_under_one_hundred_thousand_distinct_senders() {
	// The cap is the contract: feeding the limiter 100_000 distinct
	// senders must not push `state.len()` past MAX_ENTRIES. The map can
	// hold at most the cap; unseen keys beyond that are refused.
	let limiter = WindowLimiter::new(60);
	let mut admitted = 0usize;
	for i in 0..100_000 {
		if limiter.check(&format!("sender-{i}"), u32::MAX, 1_000) {
			admitted += 1;
		}
		assert!(
			limiter.len() <= MAX_ENTRIES,
			"map size {} exceeded cap {MAX_ENTRIES}",
			limiter.len()
		);
	}
	assert_eq!(limiter.len(), MAX_ENTRIES, "the map should sit at the cap");
	// Every distinct sender that fits in the cap is admitted; the rest are
	// refused. The exact split depends on the cap value but both sides are
	// non-zero, which proves the cap is doing real work.
	assert!(admitted <= MAX_ENTRIES);
	assert!(admitted > MAX_ENTRIES / 2);
}
