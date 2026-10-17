//! The hand-off from the SMTP server to the shared corpus.
//!
//! The server learns from its own decisions: mail it accepts is ham, mail it
//! rejects or quarantines is spam. That mail comes from anyone on the
//! internet, no account needed, so the learning must cost the server a fixed
//! amount however many messages arrive and whatever they hold:
//!
//! - **A bounded queue, a fixed set of workers.** At most
//!   [`QUEUE_CAPACITY`] jobs wait, each holding at most [`MAX_TRAINING_BYTES`]
//!   of text, and [`WORKERS`] workers write to the database, so the memory is
//!   about 16 MiB and the database never sees more than [`WORKERS`] training
//!   transactions at once. There is no task per message.
//! - **A share per source.** A source (the client address, and the sender's
//!   domain when it is known) may have [`MAX_PENDING_PER_SOURCE`] jobs
//!   waiting or running and may add [`MAX_PER_WINDOW`] jobs in a
//!   [`WINDOW`]; the table of sources holds [`MAX_SOURCES`] entries and
//!   refuses new ones when it is full of live ones. One client, or one
//!   domain spread over many addresses, cannot take the queue from the rest
//!   or decide the corpus on its own.
//! - **Never blocks.** [`SharedTraining::submit`] does not wait: a job that
//!   does not fit is dropped and the caller counts it. Learning is advisory;
//!   the SMTP reply never depends on it.
//!
//! The corpus cannot tell a message the attacker chose from one it should
//! learn, so the budget is the defence: what any source can teach the shared
//! corpus per hour is capped, and the server only teaches it ham from
//! senders it verified (see `Server::train_corpus`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::corpus::BayesStore;
use super::training_queue::MAX_TRAINING_BYTES;

/// Jobs the queue holds before [`SharedTraining::submit`] starts dropping.
pub const QUEUE_CAPACITY: usize = 64;

/// Workers writing to the database; also the most trainings that run at once.
pub const WORKERS: usize = 2;

/// Jobs of one source that may be waiting or running at once.
pub const MAX_PENDING_PER_SOURCE: u32 = 4;

/// Jobs one source may add in one [`WINDOW`].
pub const MAX_PER_WINDOW: u32 = 30;

/// The length of the window the per-source budget is counted in.
pub const WINDOW: Duration = Duration::from_secs(3600);

/// Sources the budget table tracks at once.
pub const MAX_SOURCES: usize = 8192;

/// Longest sender domain kept in a source key; a longer one is cut.
const MAX_DOMAIN_LEN: usize = 255;

/// Who a job comes from, as the keys its budget is counted under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrainSource {
	keys: Vec<String>,
}

impl TrainSource {
	/// The source of a message: the client address (an IPv6 address by its
	/// /64, the smallest block one customer holds) and the domain of the
	/// envelope sender. Either may be missing; with neither the job has no
	/// source and only the queue bounds it.
	pub fn new(client: Option<IpAddr>, sender_domain: Option<&str>) -> Self {
		let mut keys = Vec::new();
		if let Some(ip) = client {
			keys.push(match ip {
				IpAddr::V4(v4) => format!("ip:{v4}"),
				IpAddr::V6(v6) => {
					let [a, b, c, d, ..] = v6.segments();
					format!("ip6:{a:x}:{b:x}:{c:x}:{d:x}")
				}
			});
		}
		if let Some(domain) = sender_domain.filter(|domain| !domain.is_empty()) {
			let mut domain = domain.to_ascii_lowercase();
			if domain.len() > MAX_DOMAIN_LEN {
				let mut end = MAX_DOMAIN_LEN;
				while !domain.is_char_boundary(end) {
					end -= 1;
				}
				domain.truncate(end);
			}
			keys.push(format!("domain:{domain}"));
		}
		TrainSource { keys }
	}

	/// No source: bounded by the queue alone.
	pub fn unattributed() -> Self {
		TrainSource::default()
	}
}

/// Why a job was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
	/// The source used its jobs for this window.
	OverBudget,
	/// The source already has its share of jobs waiting or running.
	TooManyPending,
	/// The table of sources is full of live entries.
	TableFull,
	/// The queue is full.
	QueueFull,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
	window_start: Instant,
	admitted: u32,
	pending: u32,
}

/// The per-source budget.
#[derive(Debug, Default)]
pub struct Budget {
	entries: Mutex<HashMap<String, Entry>>,
}

impl Budget {
	/// Admit one job of `source` at `now`, or say why not. Every key must
	/// have room; nothing is counted unless all do.
	pub fn admit(&self, now: Instant, source: &TrainSource) -> Result<(), Refusal> {
		let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
		let mut fresh = 0;
		for key in &source.keys {
			match entries.get(key) {
				Some(entry) => {
					let in_window = now.saturating_duration_since(entry.window_start) < WINDOW;
					if in_window && entry.admitted >= MAX_PER_WINDOW {
						return Err(Refusal::OverBudget);
					}
					if entry.pending >= MAX_PENDING_PER_SOURCE {
						return Err(Refusal::TooManyPending);
					}
				}
				None => fresh += 1,
			}
		}
		if fresh > 0 && entries.len() + fresh > MAX_SOURCES {
			entries.retain(|_, entry| {
				entry.pending > 0 || now.saturating_duration_since(entry.window_start) < WINDOW
			});
			if entries.len() + fresh > MAX_SOURCES {
				return Err(Refusal::TableFull);
			}
		}
		for key in &source.keys {
			let entry = entries.entry(key.clone()).or_insert(Entry {
				window_start: now,
				admitted: 0,
				pending: 0,
			});
			if now.saturating_duration_since(entry.window_start) >= WINDOW {
				entry.window_start = now;
				entry.admitted = 0;
			}
			entry.admitted += 1;
			entry.pending += 1;
		}
		Ok(())
	}

	/// A job of `source` has finished, or was never queued.
	pub fn release(&self, source: &TrainSource) {
		let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
		for key in &source.keys {
			if let Some(entry) = entries.get_mut(key) {
				entry.pending = entry.pending.saturating_sub(1);
			}
		}
	}

	/// Sources currently tracked.
	pub fn tracked(&self) -> usize {
		self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
	}
}

/// One message to train on: a window of its bytes.
#[derive(Debug)]
pub struct Job {
	source: TrainSource,
	scope: String,
	text: Vec<u8>,
	spam: bool,
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

	/// Queue `data` (at most [`MAX_TRAINING_BYTES`] of it is kept) for
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
		self.budget.admit(now, source)?;
		let job = Job {
			source: source.clone(),
			scope: scope.to_string(),
			text: data[..data.len().min(MAX_TRAINING_BYTES)].to_vec(),
			spam,
		};
		self.sender.try_send(job).map_err(|_| {
			self.budget.release(source);
			Refusal::QueueFull
		})
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
		budget.release(&job.source);
	}
}

#[cfg(test)]
#[path = "shared_training_tests.rs"]
mod tests;
