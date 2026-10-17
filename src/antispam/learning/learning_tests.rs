//! The per-account limits on what a user's decisions may teach. No database.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::limiter::LearnLimiter;
use crate::antispam::training_queue::{TrainingJob, TrainingQueue};
use crate::metrics::Metrics;

fn at(base: Instant, seconds: u64) -> Instant {
	base + Duration::from_secs(seconds)
}

#[test]
fn an_account_over_its_minute_limit_is_refused_until_the_minute_ends() {
	let limiter = LearnLimiter::new(3, 100, 16);
	let base = Instant::now();
	for n in 0..3 {
		assert!(limiter.allow("alice", at(base, n)), "decision {n} fits");
	}
	assert!(
		!limiter.allow("alice", at(base, 3)),
		"the fourth decision in the minute is refused"
	);
	assert!(
		limiter.allow("alice", at(base, 61)),
		"a new minute starts a new count"
	);
}

#[test]
fn an_account_over_its_day_limit_is_refused_until_the_day_ends() {
	let limiter = LearnLimiter::new(100, 5, 16);
	let base = Instant::now();
	for n in 0..5 {
		assert!(
			limiter.allow("alice", at(base, n * 120)),
			"decision {n} fits"
		);
	}
	assert!(
		!limiter.allow("alice", at(base, 5 * 120)),
		"the sixth decision in the day is refused although each minute is quiet"
	);
	assert!(
		limiter.allow("alice", at(base, 24 * 3600 + 1)),
		"the next day starts a new count"
	);
}

#[test]
fn one_account_going_over_does_not_cost_another_its_turn() {
	let limiter = LearnLimiter::new(2, 100, 16);
	let base = Instant::now();
	assert!(limiter.allow("mallory", base));
	assert!(limiter.allow("mallory", base));
	assert!(!limiter.allow("mallory", base), "mallory is over the limit");
	assert!(limiter.allow("alice", base), "alice is untouched");
}

#[test]
fn many_distinct_accounts_never_grow_the_table_past_its_cap() {
	let limiter = LearnLimiter::new(10, 100, 8);
	let base = Instant::now();
	let mut accepted = 0;
	for n in 0..10_000 {
		if limiter.allow(&format!("account-{n}"), base) {
			accepted += 1;
		}
	}
	assert_eq!(accepted, 8, "only the cap's worth of accounts is tracked");
	assert!(
		limiter.allow("account-0", base),
		"a tracked account keeps its turn"
	);
	assert!(
		limiter.allow("account-new", at(base, 24 * 3600 + 1)),
		"a day later the idle windows are swept and a new account fits"
	);
}

fn job(account: &str) -> TrainingJob {
	TrainingJob {
		account: account.to_string(),
		path: std::path::PathBuf::from("/dev/null/job"),
		spam: true,
	}
}

#[test]
fn the_queue_drops_what_an_account_sends_beyond_its_limit_and_counts_it() {
	let metrics = Arc::new(Metrics::new());
	let (queue, mut receiver) = TrainingQueue::bounded(64, Arc::clone(&metrics));
	let queue = queue.with_limiter(LearnLimiter::new(5, 100, 16));
	let queued = (0..20).filter(|_| queue.submit(job("mallory"))).count();
	assert_eq!(queued, 5, "mallory gets five lessons in");
	assert!(
		queue.submit(job("alice")),
		"the queue still has room for alice after mallory's flood"
	);
	assert_eq!(
		metrics.snapshot().get("bayes_training_dropped").copied(),
		Some(15),
		"the fifteen refused lessons are counted"
	);
	let mut drained = 0;
	while receiver.try_recv().is_ok() {
		drained += 1;
	}
	assert_eq!(
		drained, 6,
		"five of mallory's and one of alice's reached the worker"
	);
}
