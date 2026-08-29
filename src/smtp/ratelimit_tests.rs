use super::*;

#[test]
fn allows_up_to_the_limit_then_blocks() {
	let limiter = SendLimiter::new(60);
	assert!(limiter.check("alice", 3, 100));
	assert!(limiter.check("alice", 3, 101));
	assert!(limiter.check("alice", 3, 102));
	// Fourth in the window is blocked.
	assert!(!limiter.check("alice", 3, 103));
}

#[test]
fn window_resets_after_elapsing() {
	let limiter = SendLimiter::new(60);
	assert!(limiter.check("alice", 2, 100));
	assert!(limiter.check("alice", 2, 110));
	assert!(!limiter.check("alice", 2, 120));
	// A new window (>= 60s after the start) resets the count.
	assert!(limiter.check("alice", 2, 160));
}

#[test]
fn accounts_are_independent_and_case_insensitive() {
	let limiter = SendLimiter::new(60);
	assert!(limiter.check("alice@example.org", 1, 100));
	assert!(!limiter.check("ALICE@example.org", 1, 100));
	// A different account has its own budget.
	assert!(limiter.check("bob@example.org", 1, 100));
}

#[test]
fn zero_limit_is_treated_as_unlimited() {
	// The policy layer is expected to skip the call when the resolved limit
	// is "no limit"; a literal 0 here is the operator's deliberate choice
	// and must not block the message.
	let limiter = SendLimiter::new(60);
	assert!(limiter.check("alice", 0, 100));
	assert!(limiter.check("alice", 0, 200));
}

#[test]
fn limit_can_change_between_calls() {
	// The policy can raise or lower a limit at any time (e.g. config reload).
	// The window count is per account, not per limit, so a tighter limit
	// immediately enforces against the existing count.
	let limiter = SendLimiter::new(60);
	assert!(limiter.check("alice", 5, 100));
	assert!(limiter.check("alice", 5, 101));
	// Operator tightens the policy to 1; the existing count of 2 is now over.
	assert!(!limiter.check("alice", 1, 102));
	// Operator relaxes to 100; the next send fits in the same window.
	assert!(limiter.check("alice", 100, 103));
}
