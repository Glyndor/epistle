//! A message that cannot be read teaches nothing and spends nothing. No
//! database: the pool cannot connect, so a lesson that reached the SQL would
//! be an error.

use std::sync::Arc;
use std::time::Duration;

use super::limiter::LearnLimiter;
use super::{LearnOutcome, Lesson};
use crate::antispam::corpus::BayesStore;
use crate::antispam::trainer::{BayesTrainer, TrainerFuture};
use crate::antispam::training_queue::{TrainingJob, TrainingQueue};
use crate::metrics::Metrics;

fn store_without_a_database() -> BayesStore {
	let pool = sqlx::postgres::PgPoolOptions::new()
		.acquire_timeout(Duration::from_millis(200))
		.connect_lazy("postgres://nobody@127.0.0.1:1/none")
		.expect("lazy pool never connects");
	BayesStore::with_key(pool, [7u8; 32])
}

#[tokio::test]
async fn a_message_that_could_not_be_read_is_not_learned_and_spends_nothing() {
	let store = store_without_a_database();
	crate::antispam::scoring_text::fail_next_reduction();
	let lesson = store
		.learn_timed("alice", b"any body text", true)
		.await
		.expect("an unread message never reaches the database");
	assert_eq!(lesson.outcome, LearnOutcome::Unread);
	let attempt = store.learn_timed("alice", b"any body text", true).await;
	assert!(
		attempt.is_err(),
		"a message that was read must reach the SQL"
	);
}

/// A trainer that answers every lesson with `Unread`.
struct NothingToRead;

impl BayesTrainer for NothingToRead {
	fn train<'a>(&'a self, _a: &'a str, _t: Vec<u8>, _s: bool) -> TrainerFuture<'a, ()> {
		Box::pin(async {})
	}
	fn learn<'a>(&'a self, _a: &'a str, _t: Vec<u8>, _s: bool) -> TrainerFuture<'a, Lesson> {
		Box::pin(async { LearnOutcome::Unread.into() })
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
async fn an_unread_message_gives_back_its_place_in_the_accounts_minute() {
	let dir = tempfile::tempdir().expect("tempdir");
	let message = dir.path().join("m.eml");
	std::fs::write(&message, b"Subject: hi\r\n\r\nbody\r\n").expect("write");
	let metrics = Arc::new(Metrics::new());
	let queue = TrainingQueue::start_with(
		Arc::new(NothingToRead),
		crate::storage::MessageCrypto::disabled(),
		Arc::clone(&metrics),
		LearnLimiter::new(1, 100, 16),
	);
	let job = || TrainingJob {
		account: "alice".to_string(),
		path: message.clone(),
		spam: true,
	};
	for round in 1..=3u64 {
		assert!(
			queue.submit(job()),
			"round {round}: the minute holds one lesson and the earlier ones taught nothing"
		);
		let mut counted = 0;
		for _ in 0..200 {
			counted = metrics
				.snapshot()
				.get("bayes_learning_unreadable")
				.copied()
				.unwrap_or(0);
			if counted == round {
				break;
			}
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
		assert_eq!(counted, round, "round {round}: counted as unreadable");
	}
}
