//! The hand-off from the SMTP server to the shared corpus.
//!
//! The server learns from its own decisions: mail it accepts is ham, mail it
//! rejects or quarantines is spam. That mail comes from anyone on the
//! internet, no account needed, so the learning must cost the server a fixed
//! amount however many messages arrive and whatever they hold:
//!
//! - **A bounded queue, a fixed set of workers.** At most
//!   [`QUEUE_CAPACITY`] jobs wait, each holding at most [`MAX_TRAINING_BYTES`](super::training_queue::MAX_TRAINING_BYTES)
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
//!   [`FINE_PER_WINDOW`]/[`COARSE_PER_WINDOW`] per [`WINDOW`].
//! - **A share of the server's budget per network.** The whole server
//!   accepts [`GLOBAL_PER_WINDOW`] jobs per kind and window, and one network
//!   (an IPv4 /16, an IPv6 /32) may take at most [`BLOCK_PER_WINDOW`] of
//!   them, a sixteenth, and may have [`NETWORK_PENDING`] jobs waiting or
//!   running over ham and spam together, a quarter of the queue. A job with
//!   no address counts as a network of its own with [`UNATTRIBUTED_PENDING`]. The last quarter of the global budget is kept for
//!   networks that have used at most [`FIRST_JOBS`] of their share: past
//!   that, a network is held back once [`SOFT_LIMIT`] is reached, while a
//!   network under its fair share keeps training until the global budget is
//!   truly spent.
//! - **Tables that cannot be filled.** Addresses, domains and networks live
//!   in separate tables of [`TABLE_SIZE`] entries each. A full table drops
//!   its least recently used entry to make room, so a flood of new keys only
//!   makes the table forget old ones, never refuses a new source; and it
//!   cannot push a domain out by rotating addresses. A forgotten key starts
//!   again from nothing, which costs the attacker nothing it did not already
//!   have: the wider keys and the global count it is also counted under
//!   remember it.
//! - **Never blocks.** [`SharedTraining::submit`] does not wait: a job that
//!   does not fit is dropped and the caller counts it. Learning is advisory;
//!   the SMTP reply never depends on it.
//!
//! The corpus cannot tell a message the attacker chose from one it should
//! learn, so the budget is the defence: what any source can teach the shared
//! corpus per hour is capped, and the server only teaches it ham from
//! senders it verified (see `Server::train_corpus`).
//!
//! # Invariants
//!
//! 1. No source can take from another more than that other's reserved part:
//!    one network never takes more than [`BLOCK_PER_WINDOW`] of the global
//!    budget in a window, never has more than [`NETWORK_PENDING`] jobs in
//!    flight (ham and spam together), and the last quarter of the global
//!    budget can be spent only by networks at or under [`FIRST_JOBS`]. So a
//!    network that uses at most [`FIRST_JOBS`] jobs a window trains whenever
//!    the other networks, each held to [`BLOCK_PER_WINDOW`], have not between
//!    them spent it all, which takes more than fifteen of them. Jobs with no
//!    address are one network of their own, held to [`UNATTRIBUTED_PENDING`]
//!    in flight and to the soft limit.
//! 2. The global budget is never exceeded: per kind and window, at most
//!    [`GLOBAL_PER_WINDOW`] jobs are admitted, at most [`BLOCK_PER_WINDOW`]
//!    of them from one network (for as long as the network stays in its
//!    table, which takes [`TABLE_SIZE`] other networks pushing it out).
//! 3. Memory is bounded: each table holds at most [`TABLE_SIZE`] keys, a key
//!    is at most a few hundred bytes, and the queue holds
//!    [`QUEUE_CAPACITY`] jobs of at most [`MAX_TRAINING_BYTES`](super::training_queue::MAX_TRAINING_BYTES).
//! 4. Refusing is cheap and leaves no state: a refused job costs a few hash
//!    lookups and changes nothing, not a count, not the order of use, not a
//!    window, and a job the queue has no room for is turned away before the
//!    budget is charged. Admitting costs a few hash lookups and ordered-map
//!    steps.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::corpus::BayesStore;
use super::scoring_text::scoring_text;

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

/// Jobs one network may have waiting or running, ham and spam together: a
/// quarter of the queue, so a network spread over its blocks cannot fill it
/// for the others.
pub const NETWORK_PENDING: u32 = 16;

/// Jobs without an address may have this many waiting or running: they are
/// one network of their own, and a small one.
pub const UNATTRIBUTED_PENDING: u32 = 4;

/// The key of that network in the table of networks. It cannot be the key
/// of an address: those are made of digits, dots and colons.
const UNATTRIBUTED_KEY: &str = "unattributed";

/// Jobs the whole server accepts per [`WINDOW`], for each of ham and spam.
pub const GLOBAL_PER_WINDOW: u32 = 2000;

/// Jobs one network (an IPv4 /16, an IPv6 /32) may add per [`WINDOW`], for
/// each of ham and spam: a sixteenth of the global budget.
pub const BLOCK_PER_WINDOW: u32 = GLOBAL_PER_WINDOW / 16;

/// The global count past which only a network at or under [`FIRST_JOBS`]
/// is still admitted: the last quarter of the budget is kept for them.
pub const SOFT_LIMIT: u32 = GLOBAL_PER_WINDOW - GLOBAL_PER_WINDOW / 4;

/// Jobs of its share a network may have used and still count as under its
/// fair share: a quarter of [`BLOCK_PER_WINDOW`].
pub const FIRST_JOBS: u32 = BLOCK_PER_WINDOW / 4;

/// The length of the window the budgets are counted in.
pub const WINDOW: Duration = Duration::from_secs(3600);

/// Entries of each table (addresses, domains).
pub const TABLE_SIZE: usize = 8192;

/// Longest domain kept in a key; a longer one is cut.
const MAX_DOMAIN_LEN: usize = 255;

/// Who a job comes from, as the keys its budget is counted under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrainSource {
	/// The client's own block, the wider block around it, and its network.
	addresses: Option<(String, String, String)>,
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
				(
					format!("{v4}"),
					format!("{a}.{b}.{c}.0/24"),
					format!("{a}.{b}.0.0/16"),
				)
			}
			IpAddr::V6(v6) => {
				let [a, b, c, d, ..] = v6.segments();
				(
					format!("{a:x}:{b:x}:{c:x}:{d:x}::/64"),
					format!("{a:x}:{b:x}:{c:x}::/48"),
					format!("{a:x}:{b:x}::/32"),
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

	/// Jobs of `key` waiting or running, ham and spam together.
	fn pending_total(&self, key: &str) -> u32 {
		self.slots.get(key).map_or(0, |slot| {
			slot.counts.iter().map(|count| count.pending).sum()
		})
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
	networks: Table,
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
				networks: Table::new(size),
				global: [Count::fresh(Instant::now()); 2],
			}),
		}
	}

	/// Admit one job of `source`, ham or spam, at `now`, or say why not.
	/// Every key must have room; nothing is counted unless all do.
	pub fn admit(&self, now: Instant, source: &TrainSource, spam: bool) -> Result<(), Refusal> {
		let kind = kind(spam);
		let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		// Everything is checked first and nothing is written until the job
		// is admitted, so a refusal leaves no trace.
		let global = inner.global[kind].at(now);
		// A source with no address is a network of its own, with a small cap.
		let (network_key, pending_cap) = match &source.addresses {
			Some((_, _, network)) => (network.as_str(), NETWORK_PENDING),
			None => (UNATTRIBUTED_KEY, UNATTRIBUTED_PENDING),
		};
		let network = inner.networks.peek(network_key, kind, now);
		network.check(BLOCK_PER_WINDOW, u32::MAX)?;
		// What a network has in flight counts over ham and spam together.
		if inner.networks.pending_total(network_key) >= pending_cap {
			return Err(Refusal::TooManyPending);
		}
		// A network that has used at most its first jobs may spend the whole
		// global budget; one that has used more, or whose network is not
		// known, stops at the soft limit and leaves the rest to the former.
		let limit = match &source.addresses {
			Some(_) if network.admitted < FIRST_JOBS => GLOBAL_PER_WINDOW,
			_ => SOFT_LIMIT,
		};
		global.check(limit, u32::MAX)?;
		if let Some((fine, coarse, _)) = &source.addresses {
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
		let mut global = global;
		global.admitted += 1;
		inner.global[kind] = global;
		if let Some((fine, coarse, _)) = &source.addresses {
			inner.addresses.charge(fine, kind, now);
			inner.addresses.charge(coarse, kind, now);
		}
		inner.networks.charge(network_key, kind, now);
		if let Some(domain) = &source.domain {
			inner.domains.charge(domain, kind, now);
		}
		Ok(())
	}

	/// A job of `source` has finished, or was never queued.
	pub fn release(&self, source: &TrainSource, spam: bool) {
		let kind = kind(spam);
		let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		if let Some((fine, coarse, _)) = &source.addresses {
			inner.addresses.release(fine, kind);
			inner.addresses.release(coarse, kind);
		}
		let network_key = match &source.addresses {
			Some((_, _, network)) => network.as_str(),
			None => UNATTRIBUTED_KEY,
		};
		inner.networks.release(network_key, kind);
		if let Some(domain) = &source.domain {
			inner.domains.release(domain, kind);
		}
	}

	/// Keys currently tracked: addresses, domains, networks.
	pub fn tracked(&self) -> (usize, usize, usize) {
		let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		(
			inner.addresses.slots.len(),
			inner.domains.slots.len(),
			inner.networks.slots.len(),
		)
	}

	/// Jobs of `source` waiting or running for ham or spam, by its most
	/// loaded key.
	pub fn pending(&self, source: &TrainSource, spam: bool) -> u32 {
		let kind = kind(spam);
		let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		let mut most = 0;
		if let Some((fine, coarse, _)) = &source.addresses {
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

	/// Queue `data`, reduced to what is read of it (see [`super::scoring_text`]),
	/// for
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
		self.budget.admit(now, source, spam)?;
		permit.send(Job {
			source: source.clone(),
			scope: scope.to_string(),
			text: scoring_text(data).text.into_bytes(),
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

#[cfg(test)]
#[path = "shared_training_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "shared_training_tests_shares.rs"]
mod tests_shares;
