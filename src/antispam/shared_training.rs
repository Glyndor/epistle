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
//! - **A budget per source, per kind.** Ham and spam are counted apart, so
//!   forged spam cannot use up what a sender may teach as ham. A source is
//!   the client address, by its own block and by the wider block around it
//!   (an IPv4 /32 and /24, an IPv6 /64 and /48), so rotating addresses
//!   inside a block does not buy a new budget; and the sender's domain, but
//!   only when the server verified it. The envelope sender is written by the
//!   client: a domain the server did not verify is never a key, or anyone
//!   could use up the budget of a domain they do not own. Each key allows
//!   [`FINE_PENDING`]/[`COARSE_PENDING`] jobs waiting or running and
//!   [`FINE_PER_WINDOW`]/[`COARSE_PER_WINDOW`] per [`WINDOW`], and the whole
//!   server [`GLOBAL_PER_WINDOW`] per kind and window.
//! - **A table that cannot be filled.** The keys of addresses and the keys
//!   of domains live in separate tables of [`TABLE_SIZE`] entries each. A
//!   full table drops its least recently used entry to make room, so a flood
//!   of new keys only makes the table forget old ones, never refuses a new
//!   source; and it cannot push a domain out by rotating addresses. A
//!   forgotten key starts again from nothing, which costs the attacker
//!   nothing it did not already have: the wider block and the global count
//!   it is also counted under remember it.
//! - **Never blocks.** [`SharedTraining::submit`] does not wait: a job that
//!   does not fit is dropped and the caller counts it. Learning is advisory;
//!   the SMTP reply never depends on it.
//!
//! The corpus cannot tell a message the attacker chose from one it should
//! learn, so the budget is the defence: what any source can teach the shared
//! corpus per hour is capped, and the server only teaches it ham from
//! senders it verified (see `Server::train_corpus`).

use std::collections::{BTreeMap, HashMap};
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

/// Jobs one address block (/32 or /64) or verified domain may have waiting or running.
pub const FINE_PENDING: u32 = 4;

/// Jobs one such key may add per [`WINDOW`], for each of ham and spam.
pub const FINE_PER_WINDOW: u32 = 30;

/// Jobs a wider address block (/24 or /48) may have waiting or running.
pub const COARSE_PENDING: u32 = 8;

/// Jobs a wider address block may add per [`WINDOW`], for each of ham and spam.
pub const COARSE_PER_WINDOW: u32 = 120;

/// Jobs the whole server accepts per [`WINDOW`], for each of ham and spam.
pub const GLOBAL_PER_WINDOW: u32 = 2000;

/// The length of the window the budgets are counted in.
pub const WINDOW: Duration = Duration::from_secs(3600);

/// Entries of each table (addresses, domains).
pub const TABLE_SIZE: usize = 8192;

/// Longest domain kept in a key; a longer one is cut.
const MAX_DOMAIN_LEN: usize = 255;

/// Who a job comes from, as the keys its budget is counted under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrainSource {
	/// The client's own block and the wider block around it.
	addresses: Option<(String, String)>,
	/// The sender's domain, only when the server verified it.
	domain: Option<String>,
}

impl TrainSource {
	/// The source of a message: the client address, and the envelope sender's
	/// domain when (and only when) the server verified it, which the caller
	/// says by passing `verified_domain`. Either may be missing; with neither
	/// the job has no source and only the queue and the global count bound it.
	pub fn new(client: Option<IpAddr>, verified_domain: Option<&str>) -> Self {
		let addresses = client.map(|ip| match ip {
			IpAddr::V4(v4) => {
				let [a, b, c, _] = v4.octets();
				(format!("{v4}"), format!("{a}.{b}.{c}.0/24"))
			}
			IpAddr::V6(v6) => {
				let [a, b, c, d, ..] = v6.segments();
				(
					format!("{a:x}:{b:x}:{c:x}:{d:x}::/64"),
					format!("{a:x}:{b:x}:{c:x}::/48"),
				)
			}
		});
		let domain = verified_domain
			.filter(|domain| !domain.is_empty())
			.map(|domain| {
				let mut domain = domain.to_ascii_lowercase();
				if domain.len() > MAX_DOMAIN_LEN {
					let mut end = MAX_DOMAIN_LEN;
					while !domain.is_char_boundary(end) {
						end -= 1;
					}
					domain.truncate(end);
				}
				domain
			});
		TrainSource { addresses, domain }
	}

	/// No source: bounded by the queue and the global count alone.
	pub fn unattributed() -> Self {
		TrainSource::default()
	}
}

/// Why a job was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
	/// A key of the source, or the whole server, used its jobs for this window.
	OverBudget,
	/// A key of the source already has its share of jobs waiting or running.
	TooManyPending,
	/// The queue is full.
	QueueFull,
}

/// One kind (ham or spam) of one key.
#[derive(Debug, Clone, Copy)]
struct Count {
	window_start: Instant,
	admitted: u32,
	pending: u32,
}

impl Count {
	fn fresh(now: Instant) -> Self {
		Count {
			window_start: now,
			admitted: 0,
			pending: 0,
		}
	}

	/// This count as of `now`: a window that is over starts again.
	fn at(mut self, now: Instant) -> Self {
		if now.saturating_duration_since(self.window_start) >= WINDOW {
			self.window_start = now;
			self.admitted = 0;
		}
		self
	}

	fn check(&self, per_window: u32, pending: u32) -> Result<(), Refusal> {
		if self.admitted >= per_window {
			Err(Refusal::OverBudget)
		} else if self.pending >= pending {
			Err(Refusal::TooManyPending)
		} else {
			Ok(())
		}
	}
}

/// The budgets of one key: index 0 is ham, 1 is spam.
#[derive(Debug, Clone, Copy)]
struct Slot {
	tick: u64,
	counts: [Count; 2],
}

/// A table of keys that forgets the least recently used one when full.
/// Every operation is a hash lookup and one ordered-map step.
#[derive(Debug)]
struct Table {
	capacity: usize,
	slots: HashMap<String, Slot>,
	recency: BTreeMap<u64, String>,
	tick: u64,
}

impl Table {
	fn new(capacity: usize) -> Self {
		Table {
			capacity,
			slots: HashMap::new(),
			recency: BTreeMap::new(),
			tick: 0,
		}
	}

	/// The count of `key` for `kind` as of `now`, fresh when the key is unknown.
	fn peek(&self, key: &str, kind: usize, now: Instant) -> Count {
		self.slots
			.get(key)
			.map_or(Count::fresh(now), |slot| slot.counts[kind].at(now))
	}

	/// Charge one job to `key`, making room for it if the table is full.
	fn charge(&mut self, key: &str, kind: usize, now: Instant) {
		self.tick += 1;
		let tick = self.tick;
		let slot = match self.slots.get_mut(key) {
			Some(slot) => {
				self.recency.remove(&slot.tick);
				slot.tick = tick;
				slot
			}
			None => {
				if self.slots.len() >= self.capacity
					&& let Some((_, oldest)) = self.recency.pop_first()
				{
					self.slots.remove(&oldest);
				}
				self.slots.entry(key.to_string()).or_insert(Slot {
					tick,
					counts: [Count::fresh(now); 2],
				})
			}
		};
		slot.tick = tick;
		let count = &mut slot.counts[kind];
		*count = count.at(now);
		count.admitted += 1;
		count.pending += 1;
		self.recency.insert(tick, key.to_string());
	}

	fn release(&mut self, key: &str, kind: usize) {
		if let Some(slot) = self.slots.get_mut(key) {
			let count = &mut slot.counts[kind];
			count.pending = count.pending.saturating_sub(1);
		}
	}
}

#[derive(Debug)]
struct Inner {
	addresses: Table,
	domains: Table,
	global: [Count; 2],
}

/// The budgets in front of the queue.
#[derive(Debug)]
pub struct Budget {
	inner: Mutex<Inner>,
}

impl Default for Budget {
	fn default() -> Self {
		Budget::with_table_size(TABLE_SIZE)
	}
}

fn kind(spam: bool) -> usize {
	usize::from(spam)
}

impl Budget {
	/// A budget whose two tables hold `size` keys each.
	pub fn with_table_size(size: usize) -> Self {
		Budget {
			inner: Mutex::new(Inner {
				addresses: Table::new(size),
				domains: Table::new(size),
				global: [Count::fresh(Instant::now()); 2],
			}),
		}
	}

	/// Admit one job of `source`, ham or spam, at `now`, or say why not.
	/// Every key must have room; nothing is counted unless all do.
	pub fn admit(&self, now: Instant, source: &TrainSource, spam: bool) -> Result<(), Refusal> {
		let kind = kind(spam);
		let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		inner.global[kind] = inner.global[kind].at(now);
		inner.global[kind].check(GLOBAL_PER_WINDOW, u32::MAX)?;
		if let Some((fine, coarse)) = &source.addresses {
			inner
				.addresses
				.peek(fine, kind, now)
				.check(FINE_PER_WINDOW, FINE_PENDING)?;
			inner
				.addresses
				.peek(coarse, kind, now)
				.check(COARSE_PER_WINDOW, COARSE_PENDING)?;
		}
		if let Some(domain) = &source.domain {
			inner
				.domains
				.peek(domain, kind, now)
				.check(FINE_PER_WINDOW, FINE_PENDING)?;
		}
		inner.global[kind].admitted += 1;
		if let Some((fine, coarse)) = &source.addresses {
			inner.addresses.charge(fine, kind, now);
			inner.addresses.charge(coarse, kind, now);
		}
		if let Some(domain) = &source.domain {
			inner.domains.charge(domain, kind, now);
		}
		Ok(())
	}

	/// A job of `source` has finished, or was never queued.
	pub fn release(&self, source: &TrainSource, spam: bool) {
		let kind = kind(spam);
		let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		if let Some((fine, coarse)) = &source.addresses {
			inner.addresses.release(fine, kind);
			inner.addresses.release(coarse, kind);
		}
		if let Some(domain) = &source.domain {
			inner.domains.release(domain, kind);
		}
	}

	/// Keys currently tracked: addresses, then domains.
	pub fn tracked(&self) -> (usize, usize) {
		let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		(inner.addresses.slots.len(), inner.domains.slots.len())
	}

	/// Jobs of `source` waiting or running for ham or spam, by its most
	/// loaded key.
	pub fn pending(&self, source: &TrainSource, spam: bool) -> u32 {
		let kind = kind(spam);
		let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		let mut most = 0;
		if let Some((fine, coarse)) = &source.addresses {
			for key in [fine, coarse] {
				most = most.max(inner.addresses.peek(key, kind, Instant::now()).pending);
			}
		}
		if let Some(domain) = &source.domain {
			most = most.max(inner.domains.peek(domain, kind, Instant::now()).pending);
		}
		most
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
		self.budget.admit(now, source, spam)?;
		let job = Job {
			source: source.clone(),
			scope: scope.to_string(),
			text: data[..data.len().min(MAX_TRAINING_BYTES)].to_vec(),
			spam,
		};
		self.sender.try_send(job).map_err(|_| {
			self.budget.release(source, spam);
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
		budget.release(&job.source, job.spam);
	}
}

#[cfg(test)]
#[path = "shared_training_tests.rs"]
mod tests;
