//! The budgets in front of the queue: what a source may teach the shared
//! corpus per window, and the charge a job is admitted against.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::source::TrainSource;
use super::table::{Count, Table};

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

/// Why a job was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
	/// A key of the source, or the whole server, used its jobs for this window.
	OverBudget,
	/// A key of the source already has its share of jobs waiting or running.
	TooManyPending,
	/// The queue is full.
	QueueFull,
	/// The message could not be read, so there is nothing to learn from.
	Unread,
}

#[derive(Debug)]
pub(super) struct Inner {
	addresses: Table,
	domains: Table,
	networks: Table,
	global: [Count; 2],
}

/// The budgets in front of the queue.
#[derive(Debug)]
pub struct Budget {
	pub(super) inner: Mutex<Inner>,
}

impl Default for Budget {
	fn default() -> Self {
		Budget::with_table_size(TABLE_SIZE)
	}
}

/// What [`Budget::admit_charged`] took for one job, to give back with
/// `Budget::refund`. It cannot be made or copied elsewhere.
#[derive(Debug)]
#[must_use = "a charge that is neither kept nor refunded is a job counted and never run"]
pub struct Charge {
	source: TrainSource,
	spam: bool,
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
		self.admit_charged(now, source, spam).map(drop)
	}

	/// [`Budget::admit`], handing back the charge it made, which
	/// `Budget::refund` can give back once.
	pub fn admit_charged(
		&self,
		now: Instant,
		source: &TrainSource,
		spam: bool,
	) -> Result<Charge, Refusal> {
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
		Ok(Charge {
			source: source.clone(),
			spam,
		})
	}

	/// A job of `source` has finished, or was never queued.
	pub fn release(&self, source: &TrainSource, spam: bool) {
		self.give_back(source, spam, false);
	}

	/// A job that was admitted will not run: it is not held against any key,
	/// nor counted in their windows. The charge is spent by it, so a job
	/// cannot be given back twice, or without having been charged.
	pub(crate) fn refund(&self, charge: Charge) {
		self.give_back(&charge.source, charge.spam, true);
	}

	fn give_back(&self, source: &TrainSource, spam: bool, refund: bool) {
		let kind = kind(spam);
		let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
		let undo = |table: &mut Table, key: &str| {
			if refund {
				table.refund(key, kind);
			} else {
				table.release(key, kind);
			}
		};
		if let Some((fine, coarse, _)) = &source.addresses {
			undo(&mut inner.addresses, fine);
			undo(&mut inner.addresses, coarse);
		}
		let network_key = match &source.addresses {
			Some((_, _, network)) => network.as_str(),
			None => UNATTRIBUTED_KEY,
		};
		undo(&mut inner.networks, network_key);
		if let Some(domain) = &source.domain {
			undo(&mut inner.domains, domain);
		}
		if refund {
			let global = &mut inner.global[kind];
			global.admitted = global.admitted.saturating_sub(1);
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
