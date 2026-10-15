//! The thread that runs submission scans. The routing sink is synchronous
//! and clamd's client is async, so one thread with one current-thread
//! runtime is started with the sink and takes every scan over a channel;
//! scans run on it concurrently, and a caller blocks only on its own answer.
//! It ends when the sink is dropped and the channel closes.
//!
//! Both the queue and the scans in flight are capped: each queued job
//! holds a whole message, so an unbounded queue let one sender pile up
//! memory and clamd connections. A full queue answers busy at once.

use std::sync::Arc;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::ThreadId;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::sync::mpsc::{Sender, channel};

use super::super::clamd::{ClamdHook, Inspection};

/// Slack on top of the clamd deadline before a caller stops waiting. The
/// exchange itself is bounded by `clamd_timeout_secs`; this only covers
/// a scanner thread that is gone or starved.
const SLACK: Duration = Duration::from_secs(5);

/// Scans clamd works on at once.
pub(super) const MAX_IN_FLIGHT: usize = 16;

/// Scans waiting for a slot; past this a submission is told to retry.
pub(super) const MAX_QUEUED: usize = 64;

/// One scan: the message and where to send the answer.
struct Job {
	raw: Vec<u8>,
	answer: SyncSender<(Inspection, ThreadId)>,
}

/// The handle the sink keeps.
pub(super) struct Scanner {
	jobs: Sender<Job>,
	deadline: Duration,
}

impl Scanner {
	/// Start the scanner thread for `clamd`.
	pub(super) fn start(clamd: Arc<ClamdHook>) -> std::io::Result<Self> {
		Self::start_with(clamd, MAX_IN_FLIGHT, MAX_QUEUED)
	}

	/// Start the scanner thread with these caps (each at least one).
	pub(super) fn start_with(
		clamd: Arc<ClamdHook>,
		in_flight: usize,
		queued: usize,
	) -> std::io::Result<Self> {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()?;
		let deadline = clamd.timeout() + SLACK;
		let (jobs, mut queue) = channel::<Job>(queued.max(1));
		let slots = Arc::new(Semaphore::new(in_flight.max(1)));
		std::thread::Builder::new()
			.name("submission-scan".into())
			.spawn(move || {
				runtime.block_on(async move {
					// Take a job only with a free slot, so jobs past the slots
					// stay in the bounded queue and a full queue is visible
					// to the sender.
					while let Ok(slot) = Arc::clone(&slots).acquire_owned().await {
						let Some(job) = queue.recv().await else {
							break;
						};
						let clamd = Arc::clone(&clamd);
						tokio::spawn(async move {
							// clamd's own deadline bounds the exchange; this one
							// also bounds anything around it, so a slot always
							// comes back.
							let inspection =
								tokio::time::timeout(deadline, clamd.inspect(&job.raw))
									.await
									.unwrap_or(Inspection::Unscanned);
							let _ = job.answer.send((inspection, std::thread::current().id()));
							drop(slot);
						});
					}
				});
			})?;
		Ok(Scanner { jobs, deadline })
	}

	/// Free places in the queue.
	#[cfg(test)]
	pub(super) fn queue_space(&self) -> usize {
		self.jobs.capacity()
	}

	/// Scan `raw` on the scanner thread and wait for the answer, with the
	/// id of the thread that scanned, or `None` at once when the queue is
	/// full. A scanner that is gone or does not answer in time leaves the
	/// message unscanned, which the caller treats as `clamd_on_error` says.
	pub(super) fn scan(&self, raw: &[u8]) -> Option<(Inspection, Option<ThreadId>)> {
		let (answer, answered) = sync_channel(1);
		let job = Job {
			raw: raw.to_vec(),
			answer,
		};
		match self.jobs.try_send(job) {
			Ok(()) => {}
			Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
				tracing::warn!("submission scanner queue is full; asking the client to retry");
				return None;
			}
			Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
				tracing::warn!("submission scanner is gone; accepting unscanned");
				return Some((Inspection::Unscanned, None));
			}
		}
		Some(match answered.recv_timeout(self.deadline) {
			Ok((inspection, worker)) => (inspection, Some(worker)),
			Err(_) => {
				tracing::warn!("submission scanner did not answer; accepting unscanned");
				(Inspection::Unscanned, None)
			}
		})
	}
}
