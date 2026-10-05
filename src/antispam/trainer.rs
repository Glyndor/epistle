//! Per-account Bayesian training: the trainer abstraction.
//!
//! A user who sets or clears `$Junk` / `$NotJunk` on a message (RFC 8621
//! section 4.1.1, RFC 9051 section 2.3.2) teaches the corpus scope of
//! their own account. The IMAP STORE path and the JMAP `Email/set` path
//! both reach the trainer through the bounded queue in
//! [`super::training_queue`]; the SMTP server reads the same store to
//! score inbound mail. The shared corpus is trained elsewhere, from the
//! server's own accept and reject decisions.
//!
//! The trait is object-safe through boxed futures, the same shape
//! [`super::bans::BanStore`] uses, so a unit test can put a recording
//! fake behind the handle without a database.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use super::bayes::Corpus;

/// The boxed future every [`BayesTrainer`] method returns.
pub type TrainerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the corpus does with a user's junk mark.
///
/// Training is advisory: an implementation logs a failed write and
/// returns, so a database error never reaches the client that set the
/// keyword.
pub trait BayesTrainer: Send + Sync {
	/// Train the scope of `account` with `text` as spam or ham. `account`
	/// is the directory-resolved account name. The empty string names the
	/// shared scope, which this path never trains.
	fn train<'a>(&'a self, account: &'a str, text: Vec<u8>, spam: bool) -> TrainerFuture<'a, ()>;

	/// The score of `text` under the scope of `account`, falling back to
	/// the shared scope while the account has fewer than
	/// [`MIN_TRUSTED_MESSAGES`] ham or spam messages. `None` when the
	/// score could not be computed.
	fn score_for_account<'a>(
		&'a self,
		account: &'a str,
		text: &'a [u8],
	) -> TrainerFuture<'a, Option<f64>>;
}

/// A shared handle to the trainer.
pub type BayesTrainerHandle = Arc<dyn BayesTrainer>;

/// Minimum ham AND spam messages before an account scope is scored on
/// its own. Below it the shared scope answers, so an account with a
/// handful of marks does not classify on noise. Graham's "A Plan for
/// Spam" works from a few hundred messages of each kind.
pub const MIN_TRUSTED_MESSAGES: u64 = 200;

/// Whether `corpus` holds enough of both kinds to be scored on its own.
pub fn is_trusted(corpus: Corpus) -> bool {
	corpus.ham_messages >= MIN_TRUSTED_MESSAGES && corpus.spam_messages >= MIN_TRUSTED_MESSAGES
}

/// One recorded `train` call: the account, the text length and the side.
pub type RecordedCall = (String, usize, bool);

/// A trainer that records every `train` call and scores nothing. The
/// production worker drives a `BayesStore` through the same trait;
/// the recording fake lets tests assert what was queued without a
/// database.
#[derive(Debug, Default)]
pub struct RecordingTrainer {
	calls: Mutex<Vec<RecordedCall>>,
	/// A `Notify` the worker fires after every `train` call, so tests
	/// do not depend on a fixed yield budget (the worker is on the
	/// same `current_thread` runtime as the test).
	notifier: tokio::sync::Notify,
}

impl RecordingTrainer {
	/// A fresh recording trainer with no calls captured.
	pub fn new() -> Self {
		Self::default()
	}

	/// The calls recorded so far, in order.
	pub fn calls(&self) -> Vec<RecordedCall> {
		self.calls.lock().expect("calls mutex").clone()
	}

	/// Resolve as soon as the worker records a call after this method
	/// was called. Cheap on the fast path: the notifier was already
	/// fired, the awaiter returns immediately.
	pub async fn await_one_call(&self) {
		self.notifier.notified().await
	}
}

impl BayesTrainer for RecordingTrainer {
	fn train<'a>(&'a self, account: &'a str, text: Vec<u8>, spam: bool) -> TrainerFuture<'a, ()> {
		Box::pin(async move {
			self.calls
				.lock()
				.expect("calls mutex")
				.push((account.to_string(), text.len(), spam));
			self.notifier.notify_one();
		})
	}

	fn score_for_account<'a>(
		&'a self,
		_account: &'a str,
		_text: &'a [u8],
	) -> TrainerFuture<'a, Option<f64>> {
		Box::pin(async { None })
	}
}

#[cfg(test)]
#[path = "trainer_tests.rs"]
pub(crate) mod tests;
