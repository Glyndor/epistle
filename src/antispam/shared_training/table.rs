//! The tables of keys: the count of one key for one kind, and the table that
//! forgets its least recently used key when it is full.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use super::budget::{Refusal, WINDOW};

/// One kind (ham or spam) of one key.
#[derive(Debug, Clone, Copy)]
pub(super) struct Count {
	window_start: Instant,
	pub(super) admitted: u32,
	pub(super) pending: u32,
}

impl Count {
	pub(super) fn fresh(now: Instant) -> Self {
		Count {
			window_start: now,
			admitted: 0,
			pending: 0,
		}
	}

	/// This count as of `now`: a window that is over starts again.
	pub(super) fn at(mut self, now: Instant) -> Self {
		if now.saturating_duration_since(self.window_start) >= WINDOW {
			self.window_start = now;
			self.admitted = 0;
		}
		self
	}

	pub(super) fn check(&self, per_window: u32, pending: u32) -> Result<(), Refusal> {
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
pub(super) struct Slot {
	tick: u64,
	counts: [Count; 2],
}

/// A table of keys that forgets the least recently used one when full.
/// Every operation is a hash lookup and one ordered-map step.
#[derive(Debug)]
pub(super) struct Table {
	capacity: usize,
	pub(super) slots: HashMap<String, Slot>,
	recency: BTreeMap<u64, String>,
	tick: u64,
}

impl Table {
	pub(super) fn new(capacity: usize) -> Self {
		Table {
			capacity,
			slots: HashMap::new(),
			recency: BTreeMap::new(),
			tick: 0,
		}
	}

	/// The count of `key` for `kind` as of `now`, fresh when the key is unknown.
	pub(super) fn peek(&self, key: &str, kind: usize, now: Instant) -> Count {
		self.slots
			.get(key)
			.map_or(Count::fresh(now), |slot| slot.counts[kind].at(now))
	}

	/// Charge one job to `key`, making room for it if the table is full.
	pub(super) fn charge(&mut self, key: &str, kind: usize, now: Instant) {
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
	pub(super) fn pending_total(&self, key: &str) -> u32 {
		self.slots.get(key).map_or(0, |slot| {
			slot.counts.iter().map(|count| count.pending).sum()
		})
	}

	pub(super) fn release(&mut self, key: &str, kind: usize) {
		if let Some(slot) = self.slots.get_mut(key) {
			let count = &mut slot.counts[kind];
			count.pending = count.pending.saturating_sub(1);
		}
	}

	/// Take back a job that was charged and never ran.
	pub(super) fn refund(&mut self, key: &str, kind: usize) {
		self.release(key, kind);
		if let Some(slot) = self.slots.get_mut(key) {
			let count = &mut slot.counts[kind];
			count.admitted = count.admitted.saturating_sub(1);
		}
	}
}
