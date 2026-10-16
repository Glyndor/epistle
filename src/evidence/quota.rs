//! How much evidence one account, and the whole server, may add in a day.
//!
//! The kept log is verified in full every few minutes, and a verification
//! that runs too long holds transactional mail for every tenant. The log
//! grows with what its clients send, so each account has a share of the day
//! and the server a limit, and an acceptance past either is refused (`451`,
//! retry later) before anything is written.
//!
//! # Invariants
//!
//! The counts below are held to these, and `quota_tests.rs` checks them after
//! every step of random sequences of acceptances, outcomes, abandonments,
//! cancellations, restarts and new days:
//!
//! 1. **One account per record.** Every record counted is attributed to exactly
//!    one account (`unattributed` when it cannot be known), and the day's total
//!    is the sum of the accounts'.
//! 2. **Isolation.** What the server has set aside for the day (`within`) is
//!    at most the sum over the accounts of what each holds up to its own
//!    share, and never more than the day's limit. An account past its share
//!    adds nothing to it: it can take no room that another account's share
//!    could use.
//! 3. **Facts are never refused.** An outcome, an abandonment or a
//!    cancellation records something that happened. It is counted to its
//!    account, and an account past its share is turned away at its next
//!    acceptance, not at the fact.
//! 4. **Exact rollback.** An acceptance that wrote nothing gives back exactly
//!    what it reserved. One that may have been written keeps it.
//! 5. **The counts outlive the process and the day.** They are kept in a file
//!    under the evidence root, shared by the server and the commands; a new day
//!    starts the day's counts again, and what an acceptance prepaid for its
//!    outcomes is remembered until they have come.
//! 6. **Shares fit the limit.** The limit is at least [`MIN_SHARES`] shares, and
//!    what is set aside never passes it.
//!
//! The state is read and written under the file's own lock. A state file that
//! is there and cannot be read refuses acceptances rather than starting from
//! nothing: a value that cannot be read grants no more than one that can.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::day::Day;

/// The account a record is counted to when its message cannot be traced.
pub const UNATTRIBUTED: &str = "unattributed";
/// The fewest accounts' shares the day's limit must hold.
pub const MIN_SHARES: u64 = 4;
/// How many days the prepaid outcomes of a message are remembered.
const OWED_DAYS: i64 = 40;
/// What is counted at which percent of a limit the status warns.
const WARN_PERCENT: u64 = 80;
const FILE: &str = "quota.json";
const LOCK: &str = "quota.lock";

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Held {
	records: u64,
	bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Owed {
	left: u64,
	day: i64,
}

/// What the file holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
	day: i64,
	/// Records counted today, all accounts.
	total: u64,
	/// What is set aside against the day's limit: each account's records up
	/// to its share.
	within: u64,
	accounts: BTreeMap<String, Held>,
	/// Outcomes still to come of acceptances that paid for them, by queue id.
	owed: BTreeMap<String, Owed>,
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
}

/// The quota under an evidence root.
#[derive(Debug)]
pub struct Quota {
	root: PathBuf,
	limits: Limits,
	/// Serialises threads of this process; the file lock covers others.
	local: std::sync::Mutex<()>,
}

impl State {
	fn roll(&mut self, today: Day) {
		if self.day != today.0 {
			self.day = today.0;
			self.total = 0;
			self.within = 0;
			self.accounts.clear();
		}
		self.owed
			.retain(|_, owed| owed.left > 0 && today.0 - owed.day <= OWED_DAYS);
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
}

impl Quota {
	/// The quota under `evidence_root` with `limits`, cut down to fit.
	pub fn open(evidence_root: &Path, limits: Limits) -> Quota {
		Quota {
			root: evidence_root.to_path_buf(),
			limits: limits.fitted(),
			local: std::sync::Mutex::new(()),
		}
	}

	fn locked<T>(&self, work: impl FnOnce(&mut State) -> T) -> std::io::Result<T> {
		let _local = self
			.local
			.lock()
			.map_err(|_| std::io::Error::other("quota lock poisoned"))?;
		super::chain::create_private_dir(&self.root)?;
		let mut options = std::fs::OpenOptions::new();
		options.create(true).truncate(false).write(true);
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		let lock = options.open(self.root.join(LOCK))?;
		lock.lock()?;
		let mut state =
			match super::checkpoint::read_bounded(&self.root.join(FILE), 64 * 1024 * 1024)? {
				None => State::default(),
				Some(bytes) => serde_json::from_slice(&bytes)
					.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?,
			};
		let before = state.clone();
		let value = work(&mut state);
		if state != before {
			let bytes = serde_json::to_vec(&state).map_err(std::io::Error::other)?;
			crate::storage::write_secret(&self.root.join(FILE), &bytes)?;
		}
		Ok(value)
	}

	/// Reserve room for one acceptance of `account` that will owe `records`
	/// records (its own and an outcome for each recipient) and keeps `kept`
	/// bytes, or say which limit it would pass. Checking and reserving are
	/// one step.
	pub fn reserve(
		&self,
		account: &str,
		id: Uuid,
		(records, kept): (u64, u64),
		today: Day,
	) -> std::io::Result<Reservation> {
		let limits = self.limits;
		let account = account.to_string();
		let refused = self.locked(|state| {
			state.roll(today);
			let held = state.accounts.get(&account).cloned().unwrap_or_default();
			let over = |what: &str| {
				Some(std::io::Error::new(
					std::io::ErrorKind::QuotaExceeded,
					format!("{what} for today: retry later"),
				))
			};
			if held.records.saturating_add(records) > limits.account_records {
				return Err(over("this account has added as many records as it may"));
			}
			if held.bytes.saturating_add(kept) > limits.account_kept_bytes {
				return Err(over("this account has kept as many bytes as it may"));
			}
			let aside = records.min(limits.account_records.saturating_sub(held.records));
			if state.within.saturating_add(aside) > limits.day_records {
				return Err(over("the evidence log is full"));
			}
			let within = state.add(
				&account,
				records,
				kept,
				(limits.account_records, limits.day_records),
			);
			state.owed.insert(
				id.to_string(),
				Owed {
					left: records.saturating_sub(1),
					day: today.0,
				},
			);
			Ok(Reservation {
				id,
				account: account.clone(),
				records,
				kept,
				within,
				day: today.0,
			})
		})?;
		refused.map_err(|error| error.unwrap_or_else(|| std::io::Error::other("quota")))
	}

	/// Give back exactly what `held` reserved, when nothing was written.
	pub fn release(&self, held: Reservation) -> std::io::Result<()> {
		self.locked(|state| {
			state.owed.remove(&held.id.to_string());
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
		})
	}

	/// A record of message `id` was written that is a fact: an outcome, an
	/// abandonment, a cancellation. Never refused. If the acceptance prepaid
	/// for it, nothing more is counted; otherwise it is counted to `account`
	/// (or [`UNATTRIBUTED`]) now.
	pub fn fact(&self, account: Option<&str>, id: Uuid, today: Day) -> std::io::Result<()> {
		let share = (self.limits.account_records, self.limits.day_records);
		let account = account.unwrap_or(UNATTRIBUTED).to_string();
		self.locked(|state| {
			state.roll(today);
			if let Some(owed) = state.owed.get_mut(&id.to_string())
				&& owed.left > 0
			{
				owed.left -= 1;
				return;
			}
			state.add(&account, 1, 0, share);
		})
	}

	/// What to tell the operator when a limit is near or reached.
	pub fn warning(&self, today: Day) -> Option<String> {
		let limits = self.limits;
		let state = self.locked(|state| {
			state.roll(today);
			state.clone()
		});
		let state = state.ok()?;
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

	/// The state as the file holds it, for tests.
	#[cfg(test)]
	pub(crate) fn state(&self) -> State {
		self.locked(|state| state.clone()).expect("state")
	}

	/// The limits in force.
	#[cfg(test)]
	pub(crate) fn limits(&self) -> Limits {
		self.limits
	}
}

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
