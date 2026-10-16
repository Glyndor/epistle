//! How much evidence one client, and the whole server, may add in a day.
//!
//! The server verifies the whole kept log every few minutes, and a
//! verification that takes too long holds transactional mail for everybody.
//! The log grows with what its clients send, so without a bound one credential
//! that sends a great deal can make every other tenant's mail wait. Each
//! acceptance is charged to its account and to the day, for the record of the
//! acceptance and the outcome it will owe each recipient, before anything is
//! written: past a limit the acceptance is refused (the client is told to
//! retry, `451`), and the status says so well before. What was reserved is
//! given back when nothing was written. The outcomes themselves are never
//! refused: they were paid for. An account's share of the day is a tenth of
//! it, so no account, with any fan-out, uses up what the others need. The
//! counts live in memory and start again with the process.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::day::Day;

/// The limits, per UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// Records (an acceptance and the outcomes it owes) one account may add.
	pub account_records: u64,
	/// Bytes one account may have kept in full.
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

/// What is counted at which fraction of a limit the status warns.
const WARN_PERCENT: u64 = 80;

#[derive(Debug, Default)]
struct Used {
	day: Option<Day>,
	records: u64,
	accounts: BTreeMap<String, (u64, u64)>,
}

/// Room set aside for one acceptance, to be given back with
/// [`Quota::release`] if nothing came of it.
#[derive(Debug)]
#[must_use]
pub struct Reservation {
	account: String,
	records: u64,
	kept: u64,
	day: Day,
}

/// The counts, and the limits they are held to.
#[derive(Debug)]
pub struct Quota {
	limits: Limits,
	used: Mutex<Used>,
}

impl Quota {
	/// A quota with `limits`.
	pub fn new(limits: Limits) -> Self {
		Quota {
			limits,
			used: Mutex::new(Used::default()),
		}
	}

	fn rolled<'a>(&self, used: &'a mut Used, today: Day) -> &'a mut Used {
		if used.day != Some(today) {
			*used = Used {
				day: Some(today),
				..Used::default()
			};
		}
		used
	}

	/// Reserve room for one acceptance of `account` that will owe `records`
	/// records and keeps `kept` bytes, on `today`, or say which limit it would
	/// pass. Checking and reserving are one step, so concurrent submissions
	/// cannot all pass the check before any is counted.
	pub fn reserve(
		&self,
		account: &str,
		(records, kept): (u64, u64),
		today: Day,
	) -> std::io::Result<Reservation> {
		let held = Reservation {
			account: account.to_string(),
			records,
			kept,
			day: today,
		};
		let Ok(mut used) = self.used.lock() else {
			return Ok(held);
		};
		let used = self.rolled(&mut used, today);
		let (counted, bytes) = used.accounts.get(account).copied().unwrap_or_default();
		let over = |what: &str| {
			Err(std::io::Error::new(
				std::io::ErrorKind::QuotaExceeded,
				format!("{what} for today: retry later"),
			))
		};
		if used.records.saturating_add(records) > self.limits.day_records {
			return over("the evidence log is full");
		}
		if counted.saturating_add(records) > self.limits.account_records {
			return over("this account has added as many records as it may");
		}
		if bytes.saturating_add(kept) > self.limits.account_kept_bytes {
			return over("this account has kept as many bytes as it may");
		}
		used.records += records;
		let entry = used.accounts.entry(account.to_string()).or_default();
		entry.0 += records;
		entry.1 += kept;
		Ok(held)
	}

	/// Give back a reservation that wrote nothing.
	pub fn release(&self, held: Reservation) {
		let Ok(mut used) = self.used.lock() else {
			return;
		};
		if used.day != Some(held.day) {
			return;
		}
		used.records = used.records.saturating_sub(held.records);
		if let Some(entry) = used.accounts.get_mut(&held.account) {
			entry.0 = entry.0.saturating_sub(held.records);
			entry.1 = entry.1.saturating_sub(held.kept);
		}
	}

	/// What to tell the operator when a limit is near or reached.
	pub fn warning(&self, today: Day) -> Option<String> {
		let used = self.used.lock().ok()?;
		if used.day != Some(today) {
			return None;
		}
		let near = |count: u64, limit: u64| {
			count.saturating_mul(100) >= limit.saturating_mul(WARN_PERCENT)
		};
		if near(used.records, self.limits.day_records) {
			return Some(format!(
				"the evidence log took {} of {} records today: past it new acceptances are refused",
				used.records, self.limits.day_records
			));
		}
		used.accounts
			.iter()
			.find(|(_, (accepted, bytes))| {
				near(*accepted, self.limits.account_records)
					|| near(*bytes, self.limits.account_kept_bytes)
			})
			.map(|(account, (accepted, bytes))| {
				format!(
					"account {} is near its evidence limits today ({accepted} records, {bytes} bytes kept)",
					crate::log_id::account(account)
				)
			})
	}
}

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
