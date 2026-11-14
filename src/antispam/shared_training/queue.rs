//! The bounded queue of jobs, and the workers that train the corpus from
//! them.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::antispam::scoring_text::scoring_text;

use super::BayesStore;
use super::budget::{Budget, Refusal};
use super::source::TrainSource;

/// Jobs the queue holds before [`SharedTraining::submit`] starts dropping.
pub const QUEUE_CAPACITY: usize = 64;

/// Workers writing to the database; also the most trainings that run at once.
pub const WORKERS: usize = 2;

/// One message to train on: a window of its bytes.
#[derive(Debug)]
pub struct Job {
	pub(super) source: TrainSource,
	pub(super) scope: String,
	pub(super) text: Vec<u8>,
	pub(super) spam: bool,
}

/// The queue of the shared corpus and the budget in front of it.
#[derive(Debug)]
pub struct SharedTraining {
	sender: mpsc::Sender<Job>,
	budget: Arc<Budget>,
}

impl SharedTraining {
	/// A queue of `capacity` jobs and its receiving half, with no workers.
	/// [`SharedTraining::start`] is the production choice.
	pub fn bounded(capacity: usize) -> (Self, mpsc::Receiver<Job>, Arc<Budget>) {
		let (sender, receiver) = mpsc::channel(capacity);
		let budget = Arc::new(Budget::default());
		(
			SharedTraining {
				sender,
				budget: budget.clone(),
			},
			receiver,
			budget,
		)
	}

	/// Start [`WORKERS`] workers that train `store` and return the queue that
	/// feeds them. The workers end when the queue is dropped. Must be called
	/// from inside a tokio runtime.
	pub fn start(store: BayesStore) -> Self {
		let (queue, receiver, budget) = Self::bounded(QUEUE_CAPACITY);
		let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
		for _ in 0..WORKERS {
			tokio::spawn(run_worker(receiver.clone(), store.clone(), budget.clone()));
		}
		queue
	}

	/// Queue `data`, reduced to what is read of it (see
	/// [`crate::antispam::scoring_text`]), for
	/// `scope` without waiting. Returns whether it was queued.
	pub fn submit(&self, source: &TrainSource, scope: &str, data: &[u8], spam: bool) -> bool {
		self.try_submit(Instant::now(), source, scope, data, spam)
			.is_ok()
	}

	/// [`SharedTraining::submit`] at a given time, saying why a job was dropped.
	pub fn try_submit(
		&self,
		now: Instant,
		source: &TrainSource,
		scope: &str,
		data: &[u8],
		spam: bool,
	) -> Result<(), Refusal> {
		// The place in the queue is taken first and the budget charged after:
		// a queue with no room is the server's state, and a source turned away
		// for it has spent nothing.
		let permit = self.sender.try_reserve().map_err(|_| Refusal::QueueFull)?;
		let charge = self.budget.admit_charged(now, source, spam)?;
		let reduced = scoring_text(data);
		if reduced.unread {
			// Nothing to learn: the place and the share are given back.
			self.budget.refund(charge);
			return Err(Refusal::Unread);
		}
		permit.send(Job {
			source: source.clone(),
			scope: scope.to_string(),
			text: reduced.text.into_bytes(),
			spam,
		});
		Ok(())
	}
}

/// Train the jobs of `receiver` one at a time until the queue is dropped.
pub async fn run_worker(
	receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<Job>>>,
	store: BayesStore,
	budget: Arc<Budget>,
) {
	loop {
		let job = receiver.lock().await.recv().await;
		let Some(job) = job else { return };
		let text = String::from_utf8_lossy(&job.text);
		if let Err(error) = store.train(&job.scope, &text, job.spam).await {
			tracing::warn!(%error, "shared bayes training failed");
		}
		budget.release(&job.source, job.spam);
	}
}
