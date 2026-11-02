//! The day's counts, and the memory of the outcomes already paid for.

use std::collections::{BTreeMap, HashMap};

use uuid::Uuid;

use super::book::{Held, Owed};
use crate::evidence::day::Day;

/// How many days the prepaid outcomes of a message are remembered: well past
/// the five days the queue gives up on mail by default.
pub(super) const OWED_DAYS: i64 = 14;
/// The most messages whose prepaid outcomes are remembered, in all and per
/// account.
pub(super) const MAX_OWED: usize = 65_536;
pub(super) const MAX_OWED_PER_ACCOUNT: usize = 8_192;
/// Once the memory is full, an account below this many entries is still
/// admitted, whatever the average is.
const MIN_OWED_GUARANTEED: usize = 64;
/// The hard ceiling of the memory: a little above the full mark, the room
/// that accounts below their fair share have.
pub(super) const MAX_OWED_CEILING: usize = MAX_OWED + MAX_OWED / 8;

/// The book.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
	pub(crate) day: i64,
	/// Records counted today, all accounts.
	pub(crate) total: u64,
	/// What is set aside against the day's limit: each account's records up
	/// to its share, while the limit has room.
	pub(crate) within: u64,
	pub(crate) accounts: BTreeMap<String, Held>,
	/// Outcomes still to come of acceptances that paid for them, by queue id.
	pub(super) owed: BTreeMap<Uuid, Owed>,
	/// How many entries of `owed` each account has, so that asking is cheap
	/// whatever the table holds.
	pub(super) owed_per: HashMap<String, usize>,
}

impl State {
	/// Start the day's counts again when `today` is later than the book's.
	/// The day only moves forward: a clock that went back does not clear
	/// the counts. Returns the day the book is in.
	pub(crate) fn roll(&mut self, today: Day) -> i64 {
		if today.0 > self.day {
			self.day = today.0;
			self.total = 0;
			self.within = 0;
			self.accounts.clear();
			// Forgetting the old ones is the work of a new day, not of every call.
			let old: Vec<Uuid> = self
				.owed
				.iter()
				.filter(|(_, owed)| today.0 - owed.day > OWED_DAYS)
				.map(|(id, _)| *id)
				.collect();
			for id in old {
				self.untrack(id);
			}
		}
		self.day
	}

	/// Count `records` to `account`: the part up to its share, and up to what
	/// the day's limit still has, is set aside.
	pub(super) fn add(
		&mut self,
		account: &str,
		records: u64,
		kept: u64,
		(share, day): (u64, u64),
	) -> u64 {
		let held = self.accounts.entry(account.to_string()).or_default();
		let aside = records
			.min(share.saturating_sub(held.records))
			.min(day.saturating_sub(self.within));
		held.records += records;
		held.bytes += kept;
		self.total += records;
		self.within += aside;
		aside
	}

	/// Whether `account` may have one more message whose prepaid outcomes
	/// are remembered. While the memory has room, every account has its own
	/// bound. Once it is full, only the accounts below their fair share (the
	/// average over the accounts that have entries, and never less than
	/// [`MIN_OWED_GUARANTEED`]) go on, up to a ceiling a little above the
	/// full mark; the ones above it wait. Nothing is ever taken from anybody.
	/// Every question is a few lookups, whatever the memory holds.
	pub(super) fn has_room_for(&self, account: &str) -> bool {
		let mine = self.owed_per.get(account).copied().unwrap_or(0);
		if mine >= MAX_OWED_PER_ACCOUNT {
			return false;
		}
		let held = self.owed.len();
		if held < MAX_OWED {
			return true;
		}
		let fair = (held / self.owed_per.len().max(1)).max(MIN_OWED_GUARANTEED);
		held < MAX_OWED_CEILING && mine < fair
	}

	/// Remember that message `id` has `owed.left` prepaid outcomes to come.
	/// Nothing is ever forgotten to make room: callers ask [`has_room_for`]
	/// first, and refuse the acceptance when there is none.
	pub(super) fn track(&mut self, id: Uuid, owed: Owed) {
		let account = owed.account.clone();
		// An id already there is replaced, not added: the counts follow the table.
		if let Some(old) = self.owed.insert(id, owed) {
			self.uncount(&old.account);
		}
		*self.owed_per.entry(account).or_default() += 1;
	}

	fn uncount(&mut self, account: &str) {
		if let Some(count) = self.owed_per.get_mut(account) {
			*count = count.saturating_sub(1);
			if *count == 0 {
				self.owed_per.remove(account);
			}
		}
	}

	pub(super) fn untrack(&mut self, id: Uuid) {
		if let Some(owed) = self.owed.remove(&id) {
			self.uncount(&owed.account);
		}
	}
}
