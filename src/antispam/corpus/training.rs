//! What changes a corpus: a message queued for the shared corpus or trained on
//! directly, the trainer the user marks go through, and dropping a whole scope.

use crate::antispam::learning::{LearnOutcome, Lesson};
use crate::antispam::scoring_text::scoring_text;
use crate::antispam::shared_training::{SharedTraining, TrainSource};
use crate::antispam::trainer::{BayesTrainer, TrainerFuture};

use super::{BayesStore, SHARED, scoring_scope};

impl BayesStore {
	/// Queue one message for the shared corpus and return whether it was
	/// accepted. Never waits and never fails the caller: a source over its
	/// share, a full queue or an untracked source (see
	/// [`crate::antispam::shared_training`]) drops the job and returns
	/// `false`. Must be called from inside a tokio runtime.
	pub fn submit_training(
		&self,
		source: &TrainSource,
		scope: &str,
		data: &[u8],
		spam: bool,
	) -> bool {
		self.shared
			.get_or_init(|| SharedTraining::start(self.detached()))
			.submit(source, scope, data, spam)
	}

	/// Train in the background without a named source, logging on failure.
	/// The job goes through the same bounded queue as
	/// [`BayesStore::submit_training`]; the queue and its workers bound it,
	/// no source budget applies.
	pub fn train_in_background(&self, scope: String, text: String, spam: bool) {
		self.submit_training(&TrainSource::unattributed(), &scope, text.as_bytes(), spam);
	}

	/// Train the `scope` corpus on the raw message `raw`, reduced first to what
	/// is read of it (see [`crate::antispam::scoring_text`]). A message that
	/// could not be reduced has no words to count, and teaches nothing:
	/// `Ok(false)`.
	pub async fn train_message(
		&self,
		scope: &str,
		raw: &[u8],
		spam: bool,
	) -> Result<bool, sqlx::Error> {
		let reduced = scoring_text(raw);
		if reduced.unread {
			tracing::warn!("a message that could not be read was not learned from");
			return Ok(false);
		}
		self.train(scope, &reduced.text, spam).await?;
		Ok(true)
	}

	/// Drop every row of `scope`: the message totals and every token
	/// count, in one transaction. Returns the number of token rows
	/// removed. Account removal calls it so a recreated account name
	/// does not inherit the previous user's training.
	///
	/// The scope is tombstoned before the transaction starts and the
	/// tombstone is cleared when the transaction finishes, success or
	/// failure: the row cannot have been dropped if the DELETE
	/// returned an error, so a tombstone that out-lived the failure
	/// would silently drop every later training job for that scope
	/// with no error and no log line. The window the tombstone covers
	/// is the transaction itself, which the per-store serialization
	/// lock already holds for the same span, so within this process the
	/// INSERT and the DELETE cannot interleave: a worker that drained
	/// its job between the removal's start and its commit either
	/// reaches `train` while the lock is held (and queues until the
	/// DELETE is done) or reaches it after the lock is released (and
	/// sees the cleared tombstone). Training is infrequent, so holding
	/// the lock across the transaction is cheap.
	///
	/// **Known limit, per process.** The lock is per
	/// [`BayesStore`] instance and shared across its clones, so two
	/// processes do not see each other's lock: a `mail account-remove`
	/// run while the `serve` process is alive does not coordinate with
	/// the server's training worker. Cross-process removal therefore
	/// still relies on a concurrent `serve` not having training jobs in
	/// flight for the same account; in practice the server has already
	/// dropped the message files for any purged user, but the
	/// coordination is the operator's, not the helper's.
	pub async fn forget_scope(&self, scope: &str) -> Result<u64, sqlx::Error> {
		let _scope_guard = self.scope_lock.lock().await;
		{
			let mut tombstones = self
				.tombstones
				.lock()
				.unwrap_or_else(|error| error.into_inner());
			tombstones.insert(scope.to_string());
		}
		let result = self.forget_scope_inner(scope).await;
		self.tombstones
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.remove(scope);
		result
	}

	async fn forget_scope_inner(&self, scope: &str) -> Result<u64, sqlx::Error> {
		self.purge_scope(scope).await
	}
}

impl BayesTrainer for BayesStore {
	fn train<'a>(&'a self, account: &'a str, text: Vec<u8>, spam: bool) -> TrainerFuture<'a, ()> {
		Box::pin(async move {
			// A user mark never trains the shared scope: that one learns
			// from the server's own accept and reject decisions.
			if account == SHARED {
				return;
			}
			if let Err(error) = self.train_message(account, &text, spam).await {
				tracing::warn!(
					account = %crate::log_id::account(account),
					%error,
					"per-account bayes training failed"
				);
			}
		})
	}

	fn learn<'a>(
		&'a self,
		account: &'a str,
		text: Vec<u8>,
		spam: bool,
	) -> TrainerFuture<'a, Lesson> {
		Box::pin(async move {
			let (outcome, busy) = BayesStore::learn_accounted(self, account, &text, spam).await;
			match outcome {
				Ok(outcome) => Lesson { outcome, busy },
				Err(error) => {
					tracing::warn!(
						account = %crate::log_id::account(account),
						%error,
						"per-account bayes learning failed"
					);
					Lesson {
						outcome: LearnOutcome::Failed,
						busy,
					}
				}
			}
		})
	}

	fn score_for_account<'a>(
		&'a self,
		account: &'a str,
		text: &'a [u8],
	) -> TrainerFuture<'a, Option<f64>> {
		Box::pin(async move {
			let trained = match self.is_trained(account).await {
				Ok(trained) => trained,
				Err(error) => {
					tracing::warn!(
						account = %crate::log_id::account(account),
						%error,
						"per-account bayes trained lookup failed"
					);
					return None;
				}
			};
			let scope = scoring_scope(trained, account);
			match self.score_message(scope, text).await {
				Ok(score) => Some(score),
				Err(error) => {
					tracing::warn!(
						account = %crate::log_id::account(account),
						%error,
						"per-account bayes score failed"
					);
					None
				}
			}
		})
	}
}
