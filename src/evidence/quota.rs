//! How much evidence one client, and the whole server, may add in a day.
//!
//! The server verifies the whole kept log every few minutes, and a
//! verification that takes too long holds transactional mail for everybody.
//! The log grows with what its clients send, so without a bound one credential
//! that sends a great deal can make every other tenant's mail wait. Each
//! acceptance is charged to its account and to the day: past a limit the
//! acceptance is refused (the client is told to retry, `451`), and the status
//! says so well before. Outcomes of mail already accepted are never refused:
//! they are owed. The counts live in memory and start again with the process.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::day::Day;

/// The limits, per UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// Acceptances one account may have recorded.
	pub account_accepted: u64,
	/// Bytes one account may have kept in full.
	pub account_kept_bytes: u64,
	/// Records of every kind the whole log may take.
	pub day_records: u64,
}

impl Default for Limits {
	fn default() -> Self {
		Limits {
			account_accepted: 200_000,
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

	/// Whether `account` may have one more acceptance recorded, keeping
	/// `kept` bytes, on `today`. An error says which limit.
	pub fn admit(&self, account: &str, kept: u64, today: Day) -> std::io::Result<()> {
		let Ok(mut used) = self.used.lock() else {
			return Ok(());
		};
		let used = self.rolled(&mut used, today);
		let (accepted, bytes) = used.accounts.get(account).copied().unwrap_or_default();
		let over = |what: &str| {
			Err(std::io::Error::new(
				std::io::ErrorKind::QuotaExceeded,
				format!("{what} for today: retry later"),
			))
		};
		if used.records >= self.limits.day_records {
			return over("the evidence log is full");
		}
		if accepted >= self.limits.account_accepted {
			return over("this account has recorded as many acceptances as it may");
		}
		if bytes.saturating_add(kept) > self.limits.account_kept_bytes {
			return over("this account has kept as many bytes as it may");
		}
		Ok(())
	}

	/// Count `records` records written for `account`, and `kept` bytes.
	pub fn charge(&self, account: Option<&str>, records: u64, kept: u64, today: Day) {
		let Ok(mut used) = self.used.lock() else {
			return;
		};
		let used = self.rolled(&mut used, today);
		used.records += records;
		if let Some(account) = account {
			let entry = used.accounts.entry(account.to_string()).or_default();
			entry.0 += records;
			entry.1 += kept;
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
				near(*accepted, self.limits.account_accepted)
					|| near(*bytes, self.limits.account_kept_bytes)
			})
			.map(|(account, (accepted, bytes))| {
				format!(
					"account {} is near its evidence limits today ({accepted} acceptances, {bytes} bytes kept)",
					crate::log_id::account(account)
				)
			})
	}
}

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
