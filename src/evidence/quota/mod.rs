//! How much evidence one account, and the whole server, may add in a day.
//!
//! The kept log is verified in full every few minutes, and a verification
//! that runs too long holds transactional mail for every tenant. The log
//! grows with what its clients send, so each account has a share of the day
//! and the server a limit, and an acceptance past either is refused (`451`,
//! retry later) before anything is written.
//!
//! There is one book, in memory, and no file of its own: at start it is
//! rebuilt from the day's records in the chain, which are already on disk,
//! signed in the day's seal and attributed (an acceptance names its account),
//! so there is no state to parse, migrate, link-check or find owned by
//! somebody else. A book that cannot be rebuilt admits no acceptance, and
//! still counts facts; it never starts from nothing in the middle of a day.
//!
//! # Invariants
//!
//! The counts below are held to these, and `quota_tests.rs` checks them after
//! every step of random sequences of acceptances, outcomes, abandonments,
//! restarts and new days:
//!
//! 1. **One account per record.** Every record counted is attributed to exactly
//!    one account (`unattributed` when it cannot be known), and the day's total
//!    is the sum of the accounts'.
//! 2. **Isolation.** What the server has set aside for the day (`within`) is
//!    at most the sum over the accounts of what each holds up to its own
//!    share, and never more than the day's limit. An account past its share
//!    adds nothing to it: it can take no room that another account's share
//!    could use.
//! 3. **Facts are never refused, and never counted twice.** An outcome, an
//!    abandonment or a cancellation records something that happened. It is
//!    counted to its account once: not at all if its acceptance paid for it,
//!    as a fact if not. An account past its share is turned away at its next
//!    acceptance, not at the fact.
//! 4. **Exact rollback.** An acceptance that wrote nothing gives back exactly
//!    what it reserved. One that may have been written keeps it.
//! 5. **The counts outlive the process and the day.** A restart rebuilds the
//!    day's counts from the chain; a new day starts the day's counts again.
//!    What a command writes from another process (a cancellation) is in the
//!    chain, and so in the book from the next start.
//! 6. **Shares fit the limit.** The limit is at least [`MIN_SHARES`] shares, and
//!    what is set aside never passes it.
//!
//! The day only moves forward. An acceptance always reserves its own record
//! and an outcome for each recipient, and the book remembers which outcomes
//! are paid for so that none is counted twice. That memory is bounded per
//! account (`MAX_OWED_PER_ACCOUNT` messages waiting for their outcomes) and
//! in all (`MAX_OWED`, room for eight accounts at their bound at once, and a
//! ceiling a little above it).
//! Nothing is ever forgotten to make room: an account with no room has its
//! acceptances refused until its outcomes come. When the whole memory is full
//! only the accounts above their fair share are refused (the others go on, up
//! to a ceiling a little above the full mark), with an alarm in the status;
//! the facts are still taken and counted. An outcome that comes after a restart, or another day,
//! is counted as a fact to the account of its acceptance when the log of the
//! last days still names it. (Mail whose evidence is not mandatory is sent
//! all the same when its acceptance cannot be recorded.)

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use uuid::Uuid;

use super::day::Day;

mod book;
mod limits;
mod rebuild;
mod state;
mod warning;

pub(crate) use book::Held;
pub use limits::{Limits, MIN_SHARES};
pub use state::State;

#[cfg(test)]
use crate::evidence::record::{Entry, RetentionMode};
use book::{Book, Owed};
#[cfg(test)]
use state::{MAX_OWED, MAX_OWED_CEILING, MAX_OWED_PER_ACCOUNT, OWED_DAYS};

/// The account a record is counted to when its message cannot be traced.
pub const UNATTRIBUTED: &str = "unattributed";

/// How often a book that could not be rebuilt tries again.
const RETRY: Duration = Duration::from_secs(30);

/// Exactly what one acceptance added, to be taken back if nothing came of it.
#[derive(Debug)]
#[must_use]
pub struct Reservation {
	id: Uuid,
	account: String,
	records: u64,
	kept: u64,
	within: u64,
	day: i64,
}

/// The quota.
#[derive(Debug)]
pub struct Quota {
	root: PathBuf,
	limits: Limits,
	book: Mutex<Book>,
}

impl Quota {
	fn book(&self) -> std::sync::MutexGuard<'_, Book> {
		self.book
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Reserve room for one acceptance of `account` for a message to
	/// `recipients` that keeps `kept` bytes, or say which limit it would pass.
	/// The reservation is its own record and an outcome for each recipient,
	/// always. Checking and reserving are one step.
	pub fn reserve(
		&self,
		account: &str,
		id: Uuid,
		(recipients, kept): (u64, u64),
		today: Day,
	) -> std::io::Result<Reservation> {
		let limits = self.limits;
		let mut book = self.book();
		self.ensure(&mut book, today);
		let over = |what: &str| {
			Err(std::io::Error::new(
				std::io::ErrorKind::QuotaExceeded,
				format!("{what} for today: retry later"),
			))
		};
		if book.unavailable.is_some() {
			if book.tried.is_none_or(|at| at.elapsed() >= RETRY) {
				self.rebuild(&mut book, today);
			}
			if book.unavailable.is_some() {
				return over("the evidence quota cannot be read");
			}
		}
		let day = book.state.roll(today);
		let records = 1 + recipients;
		if recipients > 0 && !book.state.has_room_for(account) {
			return over("too many messages of this account (or of all) wait for their outcomes");
		}
		let held = book
			.state
			.accounts
			.get(account)
			.cloned()
			.unwrap_or_default();
		if held.records.saturating_add(records) > limits.account_records {
			return over("this account has added as many records as it may");
		}
		if held.bytes.saturating_add(kept) > limits.account_kept_bytes {
			return over("this account has kept as many bytes as it may");
		}
		let aside = records.min(limits.account_records.saturating_sub(held.records));
		if book.state.within.saturating_add(aside) > limits.day_records {
			return over("the evidence log is full");
		}
		let within = book.state.add(
			account,
			records,
			kept,
			(limits.account_records, limits.day_records),
		);
		if recipients > 0 {
			book.state.track(
				id,
				Owed {
					left: recipients,
					day,
					account: account.to_string(),
				},
			);
		}
		Ok(Reservation {
			id,
			account: account.to_string(),
			records,
			kept,
			within,
			day,
		})
	}

	/// Give back exactly what `held` reserved, when nothing was written.
	pub fn release(&self, held: Reservation) {
		let mut book = self.book();
		let state = &mut book.state;
		state.untrack(held.id);
		if state.day != held.day {
			return;
		}
		state.total = state.total.saturating_sub(held.records);
		state.within = state.within.saturating_sub(held.within);
		if let Some(entry) = state.accounts.get_mut(&held.account) {
			entry.records = entry.records.saturating_sub(held.records);
			entry.bytes = entry.bytes.saturating_sub(held.kept);
			// An account the reservation introduced goes with it.
			if *entry == Held::default() {
				state.accounts.remove(&held.account);
			}
		}
	}

	/// The book, for tests.
	#[cfg(test)]
	pub(crate) fn state(&self) -> State {
		self.book().state.clone()
	}
}

#[cfg(test)]
mod tests;
