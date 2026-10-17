//! Bounded hand-off from the mail access paths to the per-account trainer.
//!
//! A client that stores `$Junk` on a whole mailbox (`STORE 1:* +FLAGS
//! ($Junk)`) produces one training job per message. The jobs go through
//! one bounded channel to one worker per process, so the memory held is
//! [`TRAINING_QUEUE_CAPACITY`] small jobs plus the single message the
//! worker is reading, and the database sees one training transaction at
//! a time, however large the mailbox is.
//!
//! A job names the message file instead of carrying its bytes. The
//! worker reads and decodes the file when it gets to it, and tokenises
//! at most [`MAX_TRAINING_BYTES`] of it (see [`super::scoring_text`]). A message expunged in between is
//! skipped.
//!
//! Training is advisory. [`TrainingQueue::submit`] never waits: when the
//! queue is full, or the account has already taught as much as
//! [`LearnLimiter`] allows, the job is dropped and counted in
//! `mail_bayes_training_dropped_total`, and the caller's reply is not
//! delayed or failed.
//!
//! The limits are per account, and each one is what keeps the accounts
//! apart. An account may have [`MAX_PENDING_PER_ACCOUNT`] jobs waiting out of
//! [`TRAINING_QUEUE_CAPACITY`], so one account, or any seven, cannot take all
//! the places; beyond seven accounts at their share the queue can be full and
//! a further account's job is dropped like any other, counted. An account
//! also has a count of lessons a minute and a day, and a bound on the time it
//! may keep the worker busy in a minute, charged from what the worker spent
//! ([`LearnLimiter`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use super::learning::limiter::LearnLimiter;
use super::trainer::BayesTrainerHandle;
use crate::metrics::Metrics;
use crate::storage::MessageCrypto;

/// Jobs the queue holds before [`TrainingQueue::submit`] starts dropping.
pub const TRAINING_QUEUE_CAPACITY: usize = 256;

/// Bytes of a message the trainer and the scorer tokenise, the size of the
/// window the SMTP path scans for URLs ([`super::urls::MAX_SCAN_BYTES`]). The
/// headers and the opening of the body carry the signal, and the end of the
/// message too; the bound keeps one large attachment from becoming tens of
/// thousands of token rows.
pub const MAX_TRAINING_BYTES: usize = super::urls::MAX_SCAN_BYTES;

/// Whether a byte can be part of a token: an ASCII letter or digit, or a byte
/// of a multi-byte character.
fn in_token(byte: u8) -> bool {
	byte.is_ascii_alphanumeric() || byte >= 0x80
}

/// The furthest back from `at` (at most) that does not cut a token in two: a
/// token is at most 30 bytes, so a run longer than that is no token and is
/// left as it is.
pub(crate) fn seam_before(bytes: &[u8], at: usize) -> usize {
	let mut cut = at;
	while at - cut <= 31 && cut > 0 && in_token(bytes[cut - 1]) && in_token(bytes[cut]) {
		cut -= 1;
	}
	if at - cut > 31 { at } else { cut }
}

/// The nearest point from `at` on (at most) that does not cut a token in two.
pub(crate) fn seam_after(bytes: &[u8], at: usize) -> usize {
	let mut cut = at;
	while cut - at <= 31 && cut < bytes.len() && in_token(bytes[cut - 1]) && in_token(bytes[cut]) {
		cut += 1;
	}
	if cut - at > 31 { at } else { cut }
}
/// Jobs one command may queue. A MOVE of ten thousand messages teaches
/// from the first of them and drops the rest, counted; the account's own
/// corpus is the only thing that misses the lesson.
pub const MAX_JOBS_PER_COMMAND: usize = 100;

/// Jobs of one account that may wait in the queue at once.
pub const MAX_PENDING_PER_ACCOUNT: usize = 32;

/// One message to train on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingJob {
	/// The directory-resolved account name: the corpus scope.
	pub account: String,
	/// The stored message file (possibly encrypted at rest).
	pub path: PathBuf,
	/// `true` trains spam, `false` trains ham.
	pub spam: bool,
}

/// What the sending half and the worker share: the per-account limits and the
/// count of jobs each account has waiting.
#[derive(Debug, Default)]
pub struct Fairness {
	limiter: LearnLimiter,
	pending: Mutex<HashMap<String, usize>>,
}

impl Fairness {
	/// Take a place in the queue for `account`, unless it already has
	/// [`MAX_PENDING_PER_ACCOUNT`] jobs waiting.
	fn reserve(&self, account: &str) -> bool {
		let mut pending = self
			.pending
			.lock()
			.unwrap_or_else(|error| error.into_inner());
		match pending.get_mut(account) {
			Some(waiting) if *waiting >= MAX_PENDING_PER_ACCOUNT => false,
			Some(waiting) => {
				*waiting += 1;
				true
			}
			None => {
				pending.insert(account.to_string(), 1);
				true
			}
		}
	}

	/// Give back a place taken by [`Fairness::reserve`].
	fn release(&self, account: &str) {
		let mut pending = self
			.pending
			.lock()
			.unwrap_or_else(|error| error.into_inner());
		if let Some(waiting) = pending.get_mut(account) {
			*waiting -= 1;
			if *waiting == 0 {
				pending.remove(account);
			}
		}
	}
}

/// The sending half, cloned into every IMAP session and the API state.
#[derive(Clone)]
pub struct TrainingQueue {
	sender: mpsc::Sender<TrainingJob>,
	metrics: Arc<Metrics>,
	fairness: Arc<Fairness>,
}

impl TrainingQueue {
	/// A queue of `capacity` jobs and its receiving half. The caller
	/// decides what drains the receiver; [`TrainingQueue::start`] is the
	/// production choice.
	pub fn bounded(capacity: usize, metrics: Arc<Metrics>) -> (Self, mpsc::Receiver<TrainingJob>) {
		let (sender, receiver) = mpsc::channel(capacity);
		let fairness = Arc::new(Fairness::default());
		(
			TrainingQueue {
				sender,
				metrics,
				fairness,
			},
			receiver,
		)
	}

	/// This queue with `limiter` in place of the default per-account limits.
	/// It starts a new count of what each account has waiting, so call it
	/// before a worker is started on the queue, as [`TrainingQueue::start_with`]
	/// does.
	pub fn with_limiter(mut self, limiter: LearnLimiter) -> Self {
		self.fairness = Arc::new(Fairness {
			limiter,
			pending: Mutex::new(HashMap::new()),
		});
		self
	}

	/// Start the one worker of this process and return the queue that
	/// feeds it. Must be called from inside a tokio runtime.
	pub fn start(
		trainer: BayesTrainerHandle,
		crypto: MessageCrypto,
		metrics: Arc<Metrics>,
	) -> Self {
		Self::start_with(trainer, crypto, metrics, LearnLimiter::default())
	}

	/// [`TrainingQueue::start`] with other per-account limits.
	pub fn start_with(
		trainer: BayesTrainerHandle,
		crypto: MessageCrypto,
		metrics: Arc<Metrics>,
		limiter: LearnLimiter,
	) -> Self {
		let (queue, receiver) = Self::bounded(TRAINING_QUEUE_CAPACITY, metrics);
		let queue = queue.with_limiter(limiter);
		let fairness = Arc::clone(&queue.fairness);
		tokio::spawn(run_worker_with(receiver, trainer, crypto, fairness));
		queue
	}

	/// Queue `job` without waiting. Returns whether it was queued. A full
	/// queue, a worker that has gone away, or an account over its limits
	/// drops the job and counts it.
	pub fn submit(&self, job: TrainingJob) -> bool {
		if !self.fairness.reserve(&job.account) {
			self.metrics.bayes_training_dropped();
			return false;
		}
		if !self
			.fairness
			.limiter
			.allow(&job.account, std::time::Instant::now())
		{
			self.fairness.release(&job.account);
			self.metrics.bayes_training_dropped();
			return false;
		}
		let account = job.account.clone();
		match self.sender.try_send(job) {
			Ok(()) => true,
			Err(_) => {
				self.fairness.release(&account);
				self.metrics.bayes_training_dropped();
				false
			}
		}
	}
}

impl TrainingQueue {
	/// Jobs of `account` waiting in the queue (tests).
	#[cfg(test)]
	pub(crate) fn pending_for(&self, account: &str) -> usize {
		let pending = self
			.fairness
			.pending
			.lock()
			.unwrap_or_else(|error| error.into_inner());
		pending.get(account).copied().unwrap_or(0)
	}

	/// Count `jobs` lessons that a command did not queue because it went
	/// over [`MAX_JOBS_PER_COMMAND`].
	pub fn note_dropped(&self, jobs: usize) {
		self.metrics
			.bayes_training_dropped_by(u64::try_from(jobs).unwrap_or(u64::MAX));
	}
}

/// Drain `receiver` until every [`TrainingQueue`] clone is gone, training
/// one message at a time. The limits of a queue made by
/// [`TrainingQueue::bounded`] are not shared with this worker; use
/// [`TrainingQueue::start`] for that.
pub async fn run_worker(
	receiver: mpsc::Receiver<TrainingJob>,
	trainer: BayesTrainerHandle,
	crypto: MessageCrypto,
) {
	run_worker_with(receiver, trainer, crypto, Arc::new(Fairness::default())).await;
}

async fn run_worker_with(
	mut receiver: mpsc::Receiver<TrainingJob>,
	trainer: BayesTrainerHandle,
	crypto: MessageCrypto,
	fairness: Arc<Fairness>,
) {
	while let Some(job) = receiver.recv().await {
		let started = std::time::Instant::now();
		let crypto = crypto.clone();
		let path = job.path.clone();
		let window = tokio::task::spawn_blocking(move || read_window(&path, &crypto)).await;
		match window {
			Ok(Ok(text)) => {
				trainer.learn(&job.account, text, job.spam).await;
			}
			Ok(Err(error)) => {
				tracing::debug!(
					account = %crate::log_id::account(&job.account),
					%error,
					"training skipped: message unreadable"
				);
			}
			Err(error) => {
				tracing::warn!(
					account = %crate::log_id::account(&job.account),
					%error,
					"training read task failed"
				);
			}
		}
		fairness
			.limiter
			.record_busy(&job.account, started.elapsed(), std::time::Instant::now());
		fairness.release(&job.account);
	}
}

/// Read and decode the message at `path`. The trainer reduces it to the text
/// it learns from (see [`super::scoring_text`]); that needs the whole message,
/// because the structure is what tells a text part from an attachment.
fn read_window(path: &std::path::Path, crypto: &MessageCrypto) -> std::io::Result<Vec<u8>> {
	let stored = std::fs::read(path)?;
	crypto.decode(&stored)
}

#[cfg(test)]
#[path = "training_queue_tests.rs"]
mod tests;
