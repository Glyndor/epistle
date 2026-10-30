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
use super::learning::{LearnOutcome, Lesson};
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

/// What one command may still queue. Every protocol command that can teach
/// (an IMAP COPY, MOVE or STORE, a JMAP `Email/set`) starts with
/// [`MAX_JOBS_PER_COMMAND`] and spends it as it queues lessons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LessonBudget {
	left: usize,
}

impl Default for LessonBudget {
	fn default() -> Self {
		Self::new()
	}
}

impl LessonBudget {
	/// The budget of one command.
	pub fn new() -> Self {
		Self::with_limit(MAX_JOBS_PER_COMMAND)
	}

	/// A budget of `lessons` (tests).
	pub fn with_limit(lessons: usize) -> Self {
		LessonBudget { left: lessons }
	}

	/// Spend up to `wanted` lessons and return how many the budget gave.
	pub fn take(&mut self, wanted: usize) -> usize {
		let granted = wanted.min(self.left);
		self.left -= granted;
		granted
	}
}

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
	command_lessons: usize,
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
				command_lessons: MAX_JOBS_PER_COMMAND,
			},
			receiver,
		)
	}

	/// This queue with another number of lessons per command (tests).
	pub fn with_command_lessons(mut self, lessons: usize) -> Self {
		self.command_lessons = lessons;
		self
	}

	/// The budget a protocol command starts with.
	pub fn command_budget(&self) -> LessonBudget {
		LessonBudget::with_limit(self.command_lessons)
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
		let metrics = Arc::clone(&queue.metrics);
		tokio::spawn(run_worker_with(
			receiver, trainer, crypto, fairness, metrics,
		));
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
	/// [`TrainingQueue::submit`] spending one lesson of `budget`; a job over
	/// the budget is dropped and counted.
	pub fn submit_within(&self, job: TrainingJob, budget: &mut LessonBudget) -> bool {
		if budget.take(1) == 0 {
			self.note_dropped(1);
			return false;
		}
		self.submit(job)
	}

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
	let (fairness, metrics) = (Arc::new(Fairness::default()), Arc::new(Metrics::new()));
	run_worker_with(receiver, trainer, crypto, fairness, metrics).await;
}

async fn run_worker_with(
	mut receiver: mpsc::Receiver<TrainingJob>,
	trainer: BayesTrainerHandle,
	crypto: MessageCrypto,
	fairness: Arc<Fairness>,
	metrics: Arc<Metrics>,
) {
	while let Some(job) = receiver.recv().await {
		let started = std::time::Instant::now();
		let crypto = crypto.clone();
		let path = job.path.clone();
		let window = tokio::task::spawn_blocking(move || read_message(&path, &crypto)).await;
		// What the account is charged: reading its message and the work of
		// its lesson. The wait behind another job's lock or for a pooled
		// connection is theirs, so it is not in the wall time of the call.
		let mut busy = started.elapsed();
		match window {
			Ok(Ok(text)) => {
				let Lesson {
					outcome,
					busy: worked,
				} = trainer.learn(&job.account, text, job.spam).await;
				busy = busy.saturating_add(worked);
				match outcome {
					LearnOutcome::Failed => metrics.bayes_learning_failed(),
					LearnOutcome::Refused | LearnOutcome::Throttled => {
						metrics.bayes_learning_refused()
					}
					LearnOutcome::Unread => {
						// Nothing was learned: the place in the account's
						// minute and day is given back.
						metrics.bayes_learning_unreadable();
						fairness.limiter.refund(&job.account);
					}
					_ => {}
				}
			}
			Ok(Err(error)) => {
				metrics.bayes_learning_unreadable();
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
			.record_busy(&job.account, busy, std::time::Instant::now());
		fairness.release(&job.account);
	}
}

/// Most a stored message file may be for the worker to read it: above the
/// largest message the server accepts by default. A file over it is counted
/// as unreadable instead of being held in memory.
pub(crate) const MAX_STORED_BYTES: u64 = 32 << 20;

/// Read and decode the message at `path`. The trainer reduces it to the text
/// it learns from (see [`super::scoring_text`]); that needs the whole message,
/// because the structure is what tells a text part from an attachment.
fn read_message(path: &std::path::Path, crypto: &MessageCrypto) -> std::io::Result<Vec<u8>> {
	read_message_from(std::fs::File::open(path)?, crypto)
}

/// [`read_message`] over any reader, taking at most [`MAX_STORED_BYTES`] of
/// it: an endless or oversized file is an error, not an allocation.
pub(crate) fn read_message_from(
	reader: impl std::io::Read,
	crypto: &MessageCrypto,
) -> std::io::Result<Vec<u8>> {
	use std::io::Read;
	let mut stored = Vec::new();
	reader.take(MAX_STORED_BYTES + 1).read_to_end(&mut stored)?;
	if stored.len() as u64 > MAX_STORED_BYTES {
		return Err(std::io::Error::other("message too large to read"));
	}
	crypto.decode(&stored)
}

#[cfg(test)]
mod tests;
