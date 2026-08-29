//! Per-account submission rate limiting: caps how many messages an
//! authenticated account may send within a sliding window, shared across all
//! connections. A compromised or runaway account cannot flood outbound mail.
//!
//! The limit per account is supplied at each [`SendLimiter::check`] call from
//! the active policy: a per-domain override, falling back to a server-wide
//! default, falling back to no limit at all. The limiter itself only owns the
//! shared window state — where the number comes from is a caller decision.

use std::collections::HashMap;
use std::sync::Mutex;

/// A shared per-account send-rate limiter.
#[derive(Debug)]
pub struct SendLimiter {
	/// Window length in seconds.
	window_secs: u64,
	/// Per-account `(window_start_epoch, count_in_window)`.
	state: Mutex<HashMap<String, (u64, u32)>>,
}

impl SendLimiter {
	/// A limiter that evaluates a per-call `limit` against a shared sliding
	/// window of `window_secs` seconds. `window_secs` is clamped to one so the
	/// window still advances on every check.
	pub fn new(window_secs: u64) -> Self {
		SendLimiter {
			window_secs: window_secs.max(1),
			state: Mutex::new(HashMap::new()),
		}
	}

	/// Record one send by `account` at `now` (epoch seconds) against the
	/// per-account `limit` (messages per window) and report whether it is
	/// within the limit. The window resets once it elapses.
	///
	/// `limit == 0` is treated as "no limit" (always allowed): the policy
	/// layer is expected to skip the call entirely when the resolved limit is
	/// `None`, so a literal zero here only appears when an operator
	/// deliberately configured it.
	pub fn check(&self, account: &str, limit: u32, now: u64) -> bool {
		if limit == 0 {
			return true;
		}
		let mut state = self.state.lock().expect("send limiter");
		let entry = state
			.entry(account.to_ascii_lowercase())
			.or_insert((now, 0));
		if now.saturating_sub(entry.0) >= self.window_secs {
			*entry = (now, 0);
		}
		if entry.1 >= limit {
			return false;
		}
		entry.1 += 1;
		true
	}
}

#[cfg(test)]
#[path = "ratelimit_tests.rs"]
mod tests;
