//! How much one account may teach its corpus.
//!
//! A user's decisions are untrusted input to a shared worker: a script that
//! moves ten thousand messages back and forth must not keep the worker busy
//! for everyone else. Each account has a count per minute and per day;
//! beyond either, the decision is dropped. Only the account's own corpus
//! could have been affected, so dropping is safe, and the drop is counted.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Decisions one account may teach per minute.
pub const PER_MINUTE: u32 = 200;
/// Decisions one account may teach per day.
pub const PER_DAY: u32 = 5_000;
/// Time of the one worker an account may use in a minute. A lesson of five
/// thousand tokens costs the database a fraction of a second, so this is the
/// bound that keeps one account from holding the worker while the others
/// wait; it is measured from what the worker did, not estimated.
pub const MAX_BUSY_PER_MINUTE: Duration = Duration::from_secs(10);
/// Accounts tracked at once. A full table that still has live windows
/// refuses accounts it does not know yet, rather than growing.
pub const MAX_ACCOUNTS: usize = 65_536;

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone, Copy)]
struct Window {
	minute_start: Instant,
	minute: u32,
	day_start: Instant,
	day: u32,
	busy: Duration,
}

impl Window {
	/// Start a new minute or a new day when the old one has ended.
	fn roll(&mut self, now: Instant) {
		if now.saturating_duration_since(self.minute_start) >= MINUTE {
			self.minute_start = now;
			self.minute = 0;
			self.busy = Duration::ZERO;
		}
		if now.saturating_duration_since(self.day_start) >= DAY {
			self.day_start = now;
			self.day = 0;
		}
	}
}

/// Fixed windows per account, held in memory. A restart forgets them,
/// which at worst lets one burst through.
#[derive(Debug)]
pub struct LearnLimiter {
	accounts: Mutex<HashMap<String, Window>>,
	per_minute: u32,
	per_day: u32,
	max_accounts: usize,
	max_busy: Duration,
}

impl Default for LearnLimiter {
	fn default() -> Self {
		Self::new(PER_MINUTE, PER_DAY, MAX_ACCOUNTS)
	}
}

impl LearnLimiter {
	/// A limiter with explicit limits (tests use small ones).
	pub fn new(per_minute: u32, per_day: u32, max_accounts: usize) -> Self {
		LearnLimiter {
			accounts: Mutex::new(HashMap::new()),
			per_minute,
			per_day,
			max_accounts,
			max_busy: MAX_BUSY_PER_MINUTE,
		}
	}

	/// This limiter with another bound on the worker time an account may
	/// use in a minute.
	pub fn with_max_busy(mut self, longest: Duration) -> Self {
		self.max_busy = longest;
		self
	}

	/// Charge `account` with the `took` the worker spent on its lesson. An
	/// account the table no longer tracks is not charged.
	pub fn record_busy(&self, account: &str, took: Duration, now: Instant) {
		let mut accounts = self
			.accounts
			.lock()
			.unwrap_or_else(|error| error.into_inner());
		if let Some(window) = accounts.get_mut(account) {
			window.roll(now);
			window.busy = window.busy.saturating_add(took);
		}
	}

	/// Whether `account` may teach one more decision at `now`, counting it
	/// when it may. Never waits.
	pub fn allow(&self, account: &str, now: Instant) -> bool {
		let mut accounts = self
			.accounts
			.lock()
			.unwrap_or_else(|error| error.into_inner());
		if !accounts.contains_key(account) && accounts.len() >= self.max_accounts {
			accounts.retain(|_, window| now.saturating_duration_since(window.day_start) < DAY);
			if accounts.len() >= self.max_accounts {
				return false;
			}
		}
		let window = accounts.entry(account.to_string()).or_insert(Window {
			minute_start: now,
			minute: 0,
			day_start: now,
			day: 0,
			busy: Duration::ZERO,
		});
		window.roll(now);
		if window.minute >= self.per_minute
			|| window.day >= self.per_day
			|| window.busy >= self.max_busy
		{
			return false;
		}
		window.minute += 1;
		window.day += 1;
		true
	}
}
