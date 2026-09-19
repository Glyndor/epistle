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
//! at most [`MAX_TRAINING_BYTES`]. A message expunged in between is
//! skipped.
//!
//! Training is advisory. [`TrainingQueue::submit`] never waits: when the
//! queue is full the job is dropped and counted in
//! `mail_bayes_training_dropped_total`, and the caller's reply is not
//! delayed or failed.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::trainer::BayesTrainerHandle;
use crate::metrics::Metrics;
use crate::storage::MessageCrypto;

/// Jobs the queue holds before [`TrainingQueue::submit`] starts dropping.
pub const TRAINING_QUEUE_CAPACITY: usize = 256;

/// Leading bytes of a message the trainer tokenises, the same window the
/// SMTP path scans for URLs ([`super::urls::MAX_SCAN_BYTES`]). The
/// headers and the opening of the body carry the signal; the bound keeps
/// one large attachment from becoming tens of thousands of token rows.
pub const MAX_TRAINING_BYTES: usize = super::urls::MAX_SCAN_BYTES;

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

/// The sending half, cloned into every IMAP session and the API state.
#[derive(Clone)]
pub struct TrainingQueue {
	sender: mpsc::Sender<TrainingJob>,
	metrics: Arc<Metrics>,
}

impl TrainingQueue {
	/// A queue of `capacity` jobs and its receiving half. The caller
	/// decides what drains the receiver; [`TrainingQueue::start`] is the
	/// production choice.
	pub fn bounded(capacity: usize, metrics: Arc<Metrics>) -> (Self, mpsc::Receiver<TrainingJob>) {
		let (sender, receiver) = mpsc::channel(capacity);
		(TrainingQueue { sender, metrics }, receiver)
	}

	/// Start the one worker of this process and return the queue that
	/// feeds it. Must be called from inside a tokio runtime.
	pub fn start(
		trainer: BayesTrainerHandle,
		crypto: MessageCrypto,
		metrics: Arc<Metrics>,
	) -> Self {
		let (queue, receiver) = Self::bounded(TRAINING_QUEUE_CAPACITY, metrics);
		tokio::spawn(run_worker(receiver, trainer, crypto));
		queue
	}

	/// Queue `job` without waiting. Returns whether it was queued. A full
	/// queue, or a worker that has gone away, drops the job and counts it.
	pub fn submit(&self, job: TrainingJob) -> bool {
		match self.sender.try_send(job) {
			Ok(()) => true,
			Err(_) => {
				self.metrics.bayes_training_dropped();
				false
			}
		}
	}
}

/// Drain `receiver` until every [`TrainingQueue`] clone is gone, training
/// one message at a time.
pub async fn run_worker(
	mut receiver: mpsc::Receiver<TrainingJob>,
	trainer: BayesTrainerHandle,
	crypto: MessageCrypto,
) {
	while let Some(job) = receiver.recv().await {
		let crypto = crypto.clone();
		let path = job.path.clone();
		let window = tokio::task::spawn_blocking(move || read_window(&path, &crypto)).await;
		match window {
			Ok(Ok(text)) => trainer.train(&job.account, text, job.spam).await,
			Ok(Err(error)) => {
				tracing::debug!(account = %job.account, %error, "training skipped: message unreadable");
			}
			Err(error) => {
				tracing::warn!(account = %job.account, %error, "training read task failed");
			}
		}
	}
}

/// Read and decode the message at `path`, keeping the training window.
fn read_window(path: &std::path::Path, crypto: &MessageCrypto) -> std::io::Result<Vec<u8>> {
	let stored = std::fs::read(path)?;
	let mut text = crypto.decode(&stored)?;
	text.truncate(MAX_TRAINING_BYTES);
	Ok(text)
}

#[cfg(test)]
#[path = "training_queue_tests.rs"]
mod tests;
