//! Facts, abandonments and the operator's warning.

use uuid::Uuid;

use super::Quota;
use super::state::MAX_OWED;
use crate::evidence::day::Day;

// In scope for the intra-doc link of `fact`.
#[allow(unused_imports)]
use super::UNATTRIBUTED;

/// What is counted at which percent of a limit the status warns.
const WARN_PERCENT: u64 = 80;

impl Quota {
	/// A record of message `id` was written that is a fact: an outcome, an
	/// abandonment. Never refused, counted once (see invariant 3), to
	/// `account` or [`UNATTRIBUTED`].
	pub fn fact(&self, account: Option<&str>, id: Uuid, today: Day) {
		self.settled(account, (id, false), today);
	}

	/// A fact that ends message `id`: an abandonment, which stands for all its
	/// outcomes. Counted like any fact, and what was still owed for the
	/// message is forgotten, so its room goes back to the account.
	pub fn ended(&self, account: Option<&str>, id: Uuid, today: Day) {
		self.settled(account, (id, true), today);
	}

	fn settled(&self, account: Option<&str>, which: (Uuid, bool), today: Day) {
		let share = (self.limits.account_records, self.limits.day_records);
		let mut book = self.book();
		self.ensure(&mut book, today);
		book.state.roll(today);
		Self::settle(&mut book.state, account, which, share);
	}

	/// What to tell the operator when a limit is near or reached, or the
	/// book is unavailable.
	pub fn warning(&self, today: Day) -> Option<String> {
		let limits = self.limits;
		let mut book = self.book();
		self.ensure(&mut book, today);
		if let Some(why) = &book.unavailable {
			return Some(format!(
				"the evidence quota cannot be read from the log ({why}): no new acceptances"
			));
		}
		book.state.roll(today);
		let state = &book.state;
		let near = |count: u64, limit: u64| {
			count.saturating_mul(100) >= limit.saturating_mul(WARN_PERCENT)
		};
		if near(state.owed.len() as u64, MAX_OWED as u64) {
			return Some(format!(
				"{} messages wait for their outcomes of the {MAX_OWED} the evidence quota remembers: past it only the accounts below their fair share are accepted",
				state.owed.len()
			));
		}
		if near(state.within, limits.day_records) {
			return Some(format!(
				"the evidence log set aside {} of {} records today: past it new acceptances are refused",
				state.within, limits.day_records
			));
		}
		state
			.accounts
			.iter()
			.find(|(_, held)| {
				near(held.records, limits.account_records)
					|| near(held.bytes, limits.account_kept_bytes)
			})
			.map(|(account, held)| {
				format!(
					"account {} is near its evidence limits today ({} records, {} bytes kept)",
					crate::log_id::account(account),
					held.records,
					held.bytes
				)
			})
	}

	/// Whether the book is waiting to be rebuilt, for tests.
	#[cfg(test)]
	pub(crate) fn unavailable(&self) -> bool {
		self.book().unavailable.is_some()
	}

	/// Try to rebuild now, for tests.
	#[cfg(test)]
	pub(crate) fn retry_now(&self, today: Day) {
		let mut book = self.book();
		self.rebuild(&mut book, today);
	}
}
