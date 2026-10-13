//! The thread that runs submission scans. The routing sink is synchronous
//! and clamd's client is async, so one thread with one current-thread
//! runtime is started with the sink and takes every scan over a channel;
//! scans run on it concurrently, and a caller blocks only on its own answer.
//! It ends when the sink is dropped and the channel closes.

use std::sync::Arc;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::ThreadId;
use std::time::Duration;

use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use super::super::clamd::{ClamdHook, Inspection};

/// Slack on top of the clamd deadline before a caller stops waiting. The
/// exchange itself is bounded by `clamd_timeout_secs`; this only covers
/// a scanner thread that is gone or starved.
const SLACK: Duration = Duration::from_secs(5);

/// One scan: the message and where to send the answer.
struct Job {
	raw: Vec<u8>,
	answer: SyncSender<(Inspection, ThreadId)>,
}

/// The handle the sink keeps.
pub(super) struct Scanner {
	jobs: UnboundedSender<Job>,
	deadline: Duration,
}

impl Scanner {
	/// Start the scanner thread for `clamd`.
	pub(super) fn start(clamd: Arc<ClamdHook>) -> std::io::Result<Self> {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()?;
		let deadline = clamd.timeout() + SLACK;
		let (jobs, mut queue) = unbounded_channel::<Job>();
		std::thread::Builder::new()
			.name("submission-scan".into())
			.spawn(move || {
				runtime.block_on(async move {
					while let Some(job) = queue.recv().await {
						let clamd = Arc::clone(&clamd);
						tokio::spawn(async move {
							let inspection = clamd.inspect(&job.raw).await;
							let _ = job.answer.send((inspection, std::thread::current().id()));
						});
					}
				});
			})?;
		Ok(Scanner { jobs, deadline })
	}

	/// Scan `raw` on the scanner thread and wait for the answer, with the
	/// id of the thread that scanned. Fails open: a scanner that is gone or
	/// does not answer in time leaves the message unscanned.
	pub(super) fn scan(&self, raw: &[u8]) -> (Inspection, Option<ThreadId>) {
		let (answer, answered) = sync_channel(1);
		let job = Job {
			raw: raw.to_vec(),
			answer,
		};
		if self.jobs.send(job).is_err() {
			tracing::warn!("submission scanner is gone; accepting unscanned");
			return (Inspection::Unscanned, None);
		}
		match answered.recv_timeout(self.deadline) {
			Ok((inspection, worker)) => (inspection, Some(worker)),
			Err(_) => {
				tracing::warn!("submission scanner did not answer; accepting unscanned");
				(Inspection::Unscanned, None)
			}
		}
	}
}
