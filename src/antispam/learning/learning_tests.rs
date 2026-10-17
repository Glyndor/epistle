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

#[test]
fn an_account_that_kept_the_worker_busy_waits_its_turn() {
	let limiter = LearnLimiter::new(1_000, 1_000, 16).with_max_busy(Duration::from_secs(10));
	let base = Instant::now();
	assert!(limiter.allow("mallory", base));
	limiter.record_busy("mallory", Duration::from_secs(11), base);
	assert!(
		!limiter.allow("mallory", at(base, 1)),
		"eleven seconds of the worker in the minute is over the budget"
	);
	assert!(
		limiter.allow("alice", at(base, 1)),
		"alice did not use the worker"
	);
	assert!(
		limiter.allow("mallory", at(base, 61)),
		"the next minute starts a new budget"
	);
}

#[test]
fn with_the_default_limits_two_accounts_flooding_leave_room_for_a_third() {
	use crate::antispam::training_queue::{MAX_PENDING_PER_ACCOUNT, TRAINING_QUEUE_CAPACITY};
	let metrics = Arc::new(Metrics::new());
	let (queue, _receiver) = TrainingQueue::bounded(TRAINING_QUEUE_CAPACITY, Arc::clone(&metrics));
	let flood = |account: &str| (0..200).filter(|_| queue.submit(job(account))).count();
	assert_eq!(flood("mallory-one"), MAX_PENDING_PER_ACCOUNT);
	assert_eq!(flood("mallory-two"), MAX_PENDING_PER_ACCOUNT);
	for account in ["alice", "bob", "carol"] {
		assert!(
			queue.submit(job(account)),
			"{account} still gets a place after two accounts hit the limits"
		);
	}
}

/// A trainer that takes `0` to answer, standing in for a slow database.
struct Slow(Duration);

impl crate::antispam::trainer::BayesTrainer for Slow {
	fn train<'a>(
		&'a self,
		_account: &'a str,
		_text: Vec<u8>,
		_spam: bool,
	) -> crate::antispam::trainer::TrainerFuture<'a, ()> {
		Box::pin(async move { tokio::time::sleep(self.0).await })
	}

	fn score_for_account<'a>(
		&'a self,
		_account: &'a str,
		_text: &'a [u8],
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>> {
		Box::pin(async { None })
	}
}

fn message_job(path: &std::path::Path, account: &str) -> TrainingJob {
	TrainingJob {
		account: account.to_string(),
		path: path.to_path_buf(),
		spam: true,
	}
}

#[tokio::test]
async fn the_worker_gives_back_the_places_it_has_served() {
	use crate::antispam::trainer::RecordingTrainer;
	use crate::antispam::training_queue::MAX_PENDING_PER_ACCOUNT;
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("m.eml");
	std::fs::write(&path, b"Subject: hi\r\n\r\nbody\r\n").expect("write");
	let trainer = Arc::new(RecordingTrainer::new());
	let queue = TrainingQueue::start_with(
		Arc::clone(&trainer) as Arc<dyn crate::antispam::trainer::BayesTrainer>,
		crate::storage::MessageCrypto::disabled(),
		Arc::new(Metrics::new()),
		LearnLimiter::new(1_000, 1_000, 16),
	);
	let accepted = (0..MAX_PENDING_PER_ACCOUNT + 1)
		.filter(|_| queue.submit(message_job(&path, "alice")))
		.count();
	assert_eq!(accepted, MAX_PENDING_PER_ACCOUNT, "the share is full");
	for _ in 0..200 {
		if trainer.calls().len() == MAX_PENDING_PER_ACCOUNT {
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	assert_eq!(
		trainer.calls().len(),
		MAX_PENDING_PER_ACCOUNT,
		"the worker served them"
	);
	assert!(
		queue.submit(message_job(&path, "alice")),
		"the places the worker served are free again"
	);
}

#[tokio::test]
async fn the_time_the_worker_spent_on_an_account_is_charged_to_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("m.eml");
	std::fs::write(&path, b"Subject: hi\r\n\r\nbody\r\n").expect("write");
	let queue = TrainingQueue::start_with(
		Arc::new(Slow(Duration::from_millis(80))),
		crate::storage::MessageCrypto::disabled(),
		Arc::new(Metrics::new()),
		LearnLimiter::new(1_000, 1_000, 16).with_max_busy(Duration::from_millis(40)),
	);
	assert!(queue.submit(message_job(&path, "mallory")));
	tokio::time::sleep(Duration::from_millis(400)).await;
	assert!(
		!queue.submit(message_job(&path, "mallory")),
		"a lesson that kept the worker for 80 ms is over a 40 ms budget"
	);
	assert!(
		queue.submit(message_job(&path, "alice")),
		"alice is not charged for mallory's time"
	);
}

#[test]
fn a_job_that_was_not_queued_does_not_keep_its_place() {
	let metrics = Arc::new(Metrics::new());
	// Refused by the limiter: five lessons a minute, twenty sent.
	let (queue, _receiver) = TrainingQueue::bounded(64, Arc::clone(&metrics));
	let queue = queue.with_limiter(LearnLimiter::new(5, 100, 16));
	let queued = (0..20).filter(|_| queue.submit(job("mallory"))).count();
	assert_eq!((queued, queue.pending_for("mallory")), (5, 5));
	// Refused because the channel is full: two places, five sent.
	let (queue, _receiver) = TrainingQueue::bounded(2, metrics);
	let queued = (0..5).filter(|_| queue.submit(job("alice"))).count();
	assert_eq!((queued, queue.pending_for("alice")), (2, 2));
}
