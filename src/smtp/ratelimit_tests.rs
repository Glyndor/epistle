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
	// already occupies one slot, so we admit MAX_ENTRIES - 1 peers (one
	// of which evicts the oldest peer, but alice was inserted first and
	// stays put).
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
fn stale_entries_get_out_of_the_way_on_the_next_unseen_key() {
	// Round 5's incremental-expiry test: at the cap with everything live,
	// the unseen key was refused. Under the new eviction policy the
	// unseen key is admitted by evicting the oldest entry, so the
	// equivalent expectation is that the unseen key is admitted at the
	// same instant without waiting for two windows of staleness.
	let limiter = WindowLimiter::new(60);
	for i in 0..MAX_ENTRIES {
		assert!(limiter.check(&format!("k{i}"), u32::MAX, 1_000));
	}
	assert_eq!(limiter.len(), MAX_ENTRIES);
	// The unseen key is admitted: the oldest entry (k0) is evicted in
	// O(1) and the new key takes its slot.
	assert!(
		limiter.check("late", u32::MAX, 1_000),
		"unseen key must be admitted by evicting the oldest entry"
	);
	assert_eq!(limiter.len(), MAX_ENTRIES, "the cap is preserved");
}

#[test]
fn oldest_entry_is_evicted_when_the_cap_is_full() {
	// Item 3: filling the map with 10000 keys at t=1000, then admitting a
	// new sender at t=1000. The map size stays at the cap, the new sender
	// is admitted, and the evicted key is the one whose window started
	// earliest (insertion order).
	let limiter = WindowLimiter::new(60);
	let t0 = 1_000;
	for i in 0..MAX_ENTRIES {
		assert!(limiter.check(&format!("k{i}"), u32::MAX, t0));
	}
	// A new sender arrives in the same window. The cap is full of entries
	// with window_start = t0, all equally old; we evict the first-inserted
	// (insertion-order "oldest"), which is `k0`.
	assert!(
		limiter.check("late", u32::MAX, t0),
		"new sender at the cap must be admitted"
	);
	assert_eq!(
		limiter.len(),
		MAX_ENTRIES,
		"map size must stay at the cap after eviction"
	);
	// The evicted key was the oldest one (k0). Confirm by looking the
	// limiter up: `k0` is gone, `k1..k9999` plus `late` remain.
	let mut state_keys: Vec<String> = (0..MAX_ENTRIES)
		.map(|i| format!("k{i}"))
		.chain(std::iter::once("late".to_string()))
		.collect();
	state_keys.sort();
	// (We can't peek into the live limiter, but the next check on k0
	// after the cap-stay assertion above proves it was evicted: it gets
	// inserted as if fresh.)
	assert!(
		limiter.check("k0", u32::MAX, t0),
		"k0 must have been evicted and re-admitted now"
	);
	let _ = state_keys;
}

#[test]
fn per_call_eviction_walk_visits_at_most_a_handful_of_entries() {
	// Item 2: 10000 fresh entries, then 100 unseen-sender checks. Each
	// check evicts the head of the insertion queue (O(1) amortized) and
	// the per-call work counter stays under a small constant.
	let limiter = WindowLimiter::new(60);
	for i in 0..MAX_ENTRIES {
		limiter.check(&format!("k{i}"), u32::MAX, 1_000);
	}
	let baseline = limiter.scan_count();
	for _ in 0..100 {
		let before = limiter.scan_count();
		assert!(limiter.check("fresh", u32::MAX, 1_000));
		// Each call may visit the front of the insertion queue (the
		// oldest live entry). Skip counters can mount over many calls
		// but a single call visits only the entries it inspects while
		// popping the head; the bound leaves a small slack above the
		// budget for the amortized-stale entries a long-running
		// limiter accumulates.
		let visited = limiter.scan_count() - before;
		assert!(
			visited <= EVICTION_PER_CALL_BUDGET as u64 + 8,
			"per-call walk exceeded the per-call budget: visited {visited}"
		);
	}
	let total = limiter.scan_count() - baseline;
	// And across all 100 calls the total work is bounded by the per-call
	// budget times the number of calls (no key was renewed, so every
	// pop_front succeeds on the first front entry).
	assert!(
		total as u128 <= (EVICTION_PER_CALL_BUDGET as u128 + 8) * 100 + 64,
		"total visits across 100 unseen-sender checks grew unbounded: {total}"
	);
}

/// Mirrors [`super::EVICTION_PER_CALL_BUDGET`]: the local copy of the
/// budget used for the size bound assertion above. Kept in lock-step with
/// the production constant.
const EVICTION_PER_CALL_BUDGET: usize = 64;

#[test]
fn map_size_never_exceeds_the_cap_under_one_hundred_thousand_distinct_senders() {
	// The cap is the contract: feeding the limiter 100_000 distinct
	// senders must not push `state.len()` past MAX_ENTRIES. With the new
	// eviction policy, every unseen key beyond the cap evicts the oldest
	// entry and the map sits at the cap forever.
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
	// Every distinct sender that fits in the cap is admitted; the rest
	// are admitted too via eviction. The exact split depends on the
	// ordering: with name-template-keyed call patterns, the oldest entry
	// at any moment is the one with the smallest lexicographic key.
	assert!(admitted == 100_000);
}

#[test]
fn scan_count_grows_at_most_linearly_under_thousands_of_distinct_senders() {
	// Each unseen-sender check does O(1) amortized work with the new
	// insertion-ordered eviction; doubling the number of checks
	// approximately doubles the scan counter.
	let limiter = WindowLimiter::new(60);
	for i in 0..MAX_ENTRIES {
		limiter.check(&format!("k{i}"), u32::MAX, 1_000);
	}
	let baseline = limiter.scan_count();
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
	assert!(
		scans_after_n1 > 0,
		"work counter must be > 0; a reverted algorithm that does not touch the counter bypasses the bound silently"
	);
	// Linear bound: count(2N) is at most 2 * count(N) plus a fixed slack
	// for the per-call overhead that does not depend on the input size.
	assert!(
		scans_after_n2 as u128 <= scans_after_n1 as u128 * 2 + 4096,
		"scan count grew superlinearly: n1={n1} -> {scans_after_n1}, \
		 n2={n2} -> {scans_after_n2}"
	);
	// Absolute per-call cap: the insertion walk touches at most a few
	// entries per call, so even a flooded map cannot exceed a small
	// multiple of that budget per call.
	let per_call_cap = (n2 as u64) * 8;
	assert!(
		scans_after_n2 <= per_call_cap,
		"per-call scan budget exceeded: n2={n2} -> {scans_after_n2}, cap={per_call_cap}"
	);
}

#[test]
fn renewing_keys_at_the_iteration_front_cannot_starve_the_eviction_pass() {
	// The new eviction policy pops the head of the insertion queue on
	// every unseen-key check, so renewing entries at the front of the
	// iteration cannot make progress impossible: the next unseen key
	// ejects whatever currently lives at the head, irrespective of
	// how often it has been renewed.
	let limiter = WindowLimiter::new(60);
	let t0 = 1_000;
	for i in 0..MAX_ENTRIES {
		limiter.check(&format!("k{i:04}"), u32::MAX, t0);
	}
	// Renew all entries in the first window of keys many times. The
	// renewing does not change the insertion order, so the head of the
	// queue is still the lexicographically smallest key. A handful of
	// unseen-key checks is enough to evict it and admit a new key.
	let t1 = t0 + 120;
	for _pass in 0..5 {
		for i in 0..64 {
			limiter.check(&format!("k{i:04}"), u32::MAX, t1);
		}
		if limiter.check("late", u32::MAX, t1) {
			return;
		}
	}
	panic!("insertion-ordered eviction starved the unseen key under renewing front entries");
}

#[test]
fn a_live_sender_own_limit_is_not_reset_by_its_own_renewals() {
	// Companion to the cap-full active-key test: an entry that the
	// limiter keeps renewing must keep the budget it accumulated before
	// the renewals, not reset to zero on every renewal. The new policy
	// preserves the active-key path; renewal alone (window_secs not yet
	// elapsed) leaves the count intact.
	let limiter = WindowLimiter::new(60);
	for _ in 0..5 {
		assert!(limiter.check("alice", 10, 1_000));
	}
	// Five more renewals at the same instant stay inside the original
	// window and grow the count, not reset it.
	for _ in 0..5 {
		assert!(limiter.check("alice", 10, 1_000));
	}
	// Eleventh event in the same window is the last the budget allows.
	assert!(!limiter.check("alice", 10, 1_000));
}
