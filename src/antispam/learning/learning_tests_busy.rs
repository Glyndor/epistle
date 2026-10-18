//! The time charged to an account is its own: the wait behind somebody else's
//! lock is not part of it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::limiter::LearnLimiter;
use super::{LearnOutcome, Lesson};
use crate::antispam::trainer::{BayesTrainer, TrainerFuture};
use crate::antispam::training_queue::{TrainingJob, TrainingQueue};
use crate::metrics::Metrics;

/// A trainer that takes `wait` of wall time and says its own work was `busy`,
/// like a lesson that queued behind another one for the store's lock.
struct WaitsBehindOthers {
	wait: Duration,
	busy: Duration,
}

impl BayesTrainer for WaitsBehindOthers {
	fn train<'a>(&'a self, _a: &'a str, _t: Vec<u8>, _s: bool) -> TrainerFuture<'a, ()> {
		Box::pin(async {})
	}
	fn learn<'a>(&'a self, _a: &'a str, _t: Vec<u8>, _s: bool) -> TrainerFuture<'a, Lesson> {
		let (wait, busy) = (self.wait, self.busy);
		Box::pin(async move {
			tokio::time::sleep(wait).await;
			Lesson {
				outcome: LearnOutcome::Learned,
				busy,
			}
		})
	}
	fn score_for_account<'a>(
		&'a self,
		_a: &'a str,
		_t: &'a [u8],
	) -> TrainerFuture<'a, Option<f64>> {
		Box::pin(async { None })
	}
}

#[tokio::test]
async fn an_account_is_not_charged_for_the_time_it_waited_behind_others() {
	let dir = tempfile::tempdir().expect("tempdir");
	let message = dir.path().join("m.eml");
	std::fs::write(&message, b"Subject: hi\r\n\r\nbody\r\n").expect("write");
	let metrics = Arc::new(Metrics::new());
	let queue = TrainingQueue::start_with(
		Arc::new(WaitsBehindOthers {
			wait: Duration::from_millis(400),
			busy: Duration::from_millis(5),
		}),
		crate::storage::MessageCrypto::disabled(),
		Arc::clone(&metrics),
		LearnLimiter::new(100, 1000, 16).with_max_busy(Duration::from_millis(200)),
	);
	let job = TrainingJob {
		account: "victim".to_string(),
		path: message,
		spam: true,
	};
	assert!(queue.submit(job.clone()), "the first lesson is accepted");
	let started = Instant::now();
	while queue.pending_for("victim") > 0 {
		assert!(
			started.elapsed() < Duration::from_secs(5),
			"the worker never finished"
		);
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	assert!(
		started.elapsed() >= Duration::from_millis(350),
		"the lesson really waited"
	);
	assert!(
		queue.submit(job),
		"a lesson that waited 400 ms but worked 5 ms leaves the account its time"
	);
}

/// A store on the database of the run, or `None` when there is none.
async fn live_store() -> Option<crate::antispam::corpus::BayesStore> {
	let url = std::env::var("DATABASE_URL")
		.ok()
		.filter(|u| !u.is_empty())?;
	let pool = crate::db::connect(&url, crate::config::DatabaseTls::Insecure, 5, None)
		.await
		.expect("connect and migrate");
	Some(crate::antispam::corpus::BayesStore::with_key(
		pool, [9u8; 32],
	))
}

/// Somebody else holds the store's lock (the training of the shared corpus
/// does) for a second and a half: the lesson that queues behind it waited, and
/// worked for milliseconds.
#[tokio::test]
async fn the_wait_behind_the_stores_lock_is_not_the_lessons_busy_time() {
	let Some(store) = live_store().await else {
		return;
	};
	let account = format!("busy-{}", uuid::Uuid::now_v7().simple());
	let holder = store.clone();
	let release = tokio::spawn(async move {
		let _held = holder.scope_lock.lock().await;
		tokio::time::sleep(Duration::from_millis(1500)).await;
	});
	tokio::time::sleep(Duration::from_millis(100)).await;
	let started = Instant::now();
	let lesson = store
		.learn_timed(&account, b"Subject: hi\r\n\r\nbuy cheap pills\r\n", true)
		.await
		.expect("lesson");
	let waited = started.elapsed();
	release.await.expect("holder");
	assert_eq!(lesson.outcome, LearnOutcome::Learned);
	assert!(
		waited >= Duration::from_millis(1300),
		"the lesson queued behind the lock ({waited:?})"
	);
	assert!(
		lesson.busy < Duration::from_millis(500),
		"{:?} of {waited:?} was charged to the account",
		lesson.busy
	);
	store.forget_scope(&account).await.expect("cleanup");
}

/// The same for a pool whose only connection is in use: the wait for it is
/// not the lesson's work either.
#[tokio::test]
async fn the_wait_for_a_pooled_connection_is_not_the_lessons_busy_time() {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
		return;
	};
	let pool = crate::db::connect(&url, crate::config::DatabaseTls::Insecure, 1, None)
		.await
		.expect("connect and migrate");
	let store = crate::antispam::corpus::BayesStore::with_key(pool.clone(), [9u8; 32]);
	let account = format!("busy-{}", uuid::Uuid::now_v7().simple());
	let held = pool.acquire().await.expect("the only connection");
	let release = tokio::spawn(async move {
		tokio::time::sleep(Duration::from_millis(1500)).await;
		drop(held);
	});
	let started = Instant::now();
	let lesson = store
		.learn_timed(&account, b"Subject: hi\r\n\r\nbuy cheap pills\r\n", true)
		.await
		.expect("lesson");
	let waited = started.elapsed();
	release.await.expect("holder");
	assert_eq!(lesson.outcome, LearnOutcome::Learned);
	assert!(
		waited >= Duration::from_millis(1300),
		"the lesson waited for the connection ({waited:?})"
	);
	assert!(
		lesson.busy < Duration::from_millis(500),
		"{:?} of {waited:?} was charged to the account",
		lesson.busy
	);
	store.forget_scope(&account).await.expect("cleanup");
}
