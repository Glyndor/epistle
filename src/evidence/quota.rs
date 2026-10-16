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
//! The day only moves forward. What is remembered of prepaid outcomes is
//! bounded in all and per account, in memory: an acceptance with no room in
//! it reserves its own record only and its outcomes are counted when they
//! come, once. An outcome that comes after a restart, or another day, is
//! counted as a fact to the account the book can name.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::chain::{CHAIN_DIR, day_file, open_day};
use super::day::Day;
use super::lines::{Line, Lines};
use super::record::{Entry, MAX_RECORDS_PER_DAY, Record, RetentionMode};

/// The account a record is counted to when its message cannot be traced.
pub const UNATTRIBUTED: &str = "unattributed";
/// The fewest accounts' shares the day's limit must hold.
pub const MIN_SHARES: u64 = 4;
/// How many days the prepaid outcomes of a message are remembered.
const OWED_DAYS: i64 = 40;
/// The most messages whose prepaid outcomes are remembered, in all and per
/// account.
const MAX_OWED: usize = 65_536;
const MAX_OWED_PER_ACCOUNT: usize = 8_192;
/// What is counted at which percent of a limit the status warns.
const WARN_PERCENT: u64 = 80;
/// How often a book that could not be rebuilt tries again.
const RETRY: Duration = Duration::from_secs(30);

/// The limits, per UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// Records (an acceptance and the outcomes it owes) one account may add:
	/// its share of the day.
	pub account_records: u64,
	/// Bytes one account may keep in full.
	pub account_kept_bytes: u64,
	/// Records of every kind the whole log may take.
	pub day_records: u64,
}

impl Default for Limits {
	fn default() -> Self {
		Limits {
			account_records: 500_000,
			account_kept_bytes: 4 * 1024 * 1024 * 1024,
			day_records: 5_000_000,
		}
	}
}

impl Limits {
	/// The limits with the share cut down so that [`MIN_SHARES`] of them fit
	/// the day, when it was set larger.
	pub fn fitted(mut self) -> Self {
		self.account_records = self.account_records.min(self.day_records / MIN_SHARES);
		self
	}
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Held {
	pub(crate) records: u64,
	pub(crate) bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Owed {
	left: u64,
	day: i64,
	account: String,
}

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
	owed: BTreeMap<Uuid, Owed>,
}

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
	owed: bool,
}

#[derive(Debug)]
struct Book {
	state: State,
	/// Whether the book was rebuilt from the log yet.
	loaded: bool,
	/// Why the book could not be rebuilt, while it cannot: acceptances wait.
	unavailable: Option<String>,
	tried: Option<Instant>,
}

/// The quota.
#[derive(Debug)]
pub struct Quota {
	root: PathBuf,
	limits: Limits,
	book: Mutex<Book>,
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
		}
		let day = self.day;
		self.owed
			.retain(|_, owed| owed.left > 0 && day - owed.day <= OWED_DAYS);
		day
	}

	/// Count `records` to `account`: the part up to its share, and up to what
	/// the day's limit still has, is set aside.
	fn add(&mut self, account: &str, records: u64, kept: u64, (share, day): (u64, u64)) -> u64 {
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

	/// Whether `account` may have prepaid outcomes remembered.
	fn has_room_for(&self, account: &str) -> bool {
		self.owed.len() < MAX_OWED
			&& self
				.owed
				.values()
				.filter(|owed| owed.account == account)
				.count() < MAX_OWED_PER_ACCOUNT
	}
}

impl Quota {
	/// The quota for the log under `evidence_root`. Its book is rebuilt from
	/// the records of the day on first use, so that starting it reads no clock.
	/// A log that cannot be read leaves the book unavailable: no acceptance
	/// until it can be.
	pub fn start(evidence_root: &Path, limits: Limits) -> Quota {
		Quota {
			root: evidence_root.to_path_buf(),
			limits: limits.fitted(),
			book: Mutex::new(Book {
				state: State::default(),
				loaded: false,
				unavailable: None,
				tried: None,
			}),
		}
	}

	/// [`start`](Self::start), rebuilt for `today` at once.
	#[cfg(test)]
	pub(crate) fn start_at(evidence_root: &Path, limits: Limits, today: Day) -> Quota {
		let quota = Self::start(evidence_root, limits);
		quota.ensure(&mut quota.book(), today);
		quota
	}

	/// Rebuild the book the first time it is used.
	fn ensure(&self, book: &mut Book, today: Day) {
		if !book.loaded {
			book.loaded = true;
			self.rebuild(book, today);
		}
	}

	/// Rebuild `book` from today's day file.
	fn rebuild(&self, book: &mut Book, today: Day) {
		book.tried = Some(Instant::now());
		match self.read_day(today) {
			Ok(state) => {
				if book.unavailable.take().is_some() {
					tracing::warn!("the evidence quota was rebuilt from the log");
				}
				// What is remembered of earlier days' outcomes stays.
				let kept = std::mem::take(&mut book.state.owed);
				book.state = state;
				for (id, owed) in kept {
					book.state.owed.entry(id).or_insert(owed);
				}
			}
			Err(error) => {
				if book.unavailable.is_none() {
					tracing::error!(%error, "the evidence quota cannot be rebuilt from the log: no new acceptances until it can");
				}
				book.unavailable = Some(error.to_string());
			}
		}
	}

	/// The counts of the records of `today` in the chain.
	fn read_day(&self, today: Day) -> std::io::Result<State> {
		let share = (self.limits.account_records, self.limits.day_records);
		let mut state = State {
			day: today.0,
			..State::default()
		};
		let file = match open_day(&day_file(&self.root.join(CHAIN_DIR), today)) {
			Ok(file) => file,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(state),
			Err(error) => return Err(error),
		};
		let mut lines = Lines::new(std::io::BufReader::new(file));
		let mut read = 0u64;
		while let Some((_, line)) = lines.next_line()? {
			read += 1;
			if read > MAX_RECORDS_PER_DAY {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"more records in a day than any day may hold",
				));
			}
			let Line::Complete(bytes) = line else {
				state.add(UNATTRIBUTED, 1, 0, share);
				continue;
			};
			match Record::parse_canonical(bytes).map(|record| record.entry) {
				Ok(Entry::Accepted(accepted)) => {
					let recipients = accepted.recipients.len() as u64;
					let paid = state.has_room_for(&accepted.account);
					let kept = match accepted.retention.mode {
						RetentionMode::Full => accepted.size,
						_ => 0,
					};
					state.add(
						&accepted.account,
						1 + if paid { recipients } else { 0 },
						kept,
						share,
					);
					if paid {
						state.owed.insert(
							accepted.spool_id,
							Owed {
								left: recipients,
								day: today.0,
								account: accepted.account.clone(),
							},
						);
					}
				}
				Ok(Entry::Outcome(super::record::Outcome { spool_id, .. }))
				| Ok(Entry::Abandoned(super::record::Abandoned { spool_id, .. })) => {
					Self::settle(&mut state, None, spool_id, share);
				}
				_ => {
					state.add(UNATTRIBUTED, 1, 0, share);
				}
			}
		}
		Ok(state)
	}

	/// Count a fact: not at all if its acceptance paid for it, else once.
	fn settle(state: &mut State, account: Option<&str>, id: Uuid, share: (u64, u64)) {
		if let Some(owed) = state.owed.get_mut(&id)
			&& owed.left > 0
		{
			owed.left -= 1;
			return;
		}
		state.add(account.unwrap_or(UNATTRIBUTED), 1, 0, share);
	}

	fn book(&self) -> std::sync::MutexGuard<'_, Book> {
		self.book
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Reserve room for one acceptance of `account` for a message to
	/// `recipients` that keeps `kept` bytes, or say which limit it would pass.
	/// The reservation is its own record and, when the book has room to
	/// remember it, an outcome for each recipient. Checking and reserving are
	/// one step.
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
		let paid = book.state.has_room_for(account);
		let records = 1 + if paid { recipients } else { 0 };
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
		if paid {
			book.state.owed.insert(
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
			owed: paid,
		})
	}

	/// Give back exactly what `held` reserved, when nothing was written.
	pub fn release(&self, held: Reservation) {
		let mut book = self.book();
		let state = &mut book.state;
		if held.owed {
			state.owed.remove(&held.id);
		}
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

	/// A record of message `id` was written that is a fact: an outcome, an
	/// abandonment. Never refused, counted once (see invariant 3), to
	/// `account` or [`UNATTRIBUTED`].
	pub fn fact(&self, account: Option<&str>, id: Uuid, today: Day) {
		let share = (self.limits.account_records, self.limits.day_records);
		let mut book = self.book();
		self.ensure(&mut book, today);
		book.state.roll(today);
		Self::settle(&mut book.state, account, id, share);
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

	/// The book, for tests.
	#[cfg(test)]
	pub(crate) fn state(&self) -> State {
		self.book().state.clone()
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

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
