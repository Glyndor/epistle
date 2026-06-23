//! Per-account submission rate limiting: caps how many messages an
//! authenticated account may send within a sliding window, shared across all
//! connections. A compromised or runaway account cannot flood outbound mail.

use std::collections::HashMap;
use std::sync::Mutex;

/// A shared per-account send-rate limiter.
#[derive(Debug)]
pub struct SendLimiter {
	/// Maximum messages allowed per account within the window.
	per_window: u32,
	/// Window length in seconds.
	window_secs: u64,
	/// Per-account `(window_start_epoch, count_in_window)`.
	state: Mutex<HashMap<String, (u64, u32)>>,
}

impl SendLimiter {
	/// A limiter allowing `per_window` messages per `window_secs` per account.
	pub fn new(per_window: u32, window_secs: u64) -> Self {
		SendLimiter {
			per_window: per_window.max(1),
			window_secs: window_secs.max(1),
			state: Mutex::new(HashMap::new()),
		}
	}

	/// Record one send by `account` at `now` (epoch seconds) and report whether
	/// it is within the limit. The window resets once it elapses.
	pub fn check(&self, account: &str, now: u64) -> bool {
		let mut state = self.state.lock().expect("send limiter");
		let entry = state
			.entry(account.to_ascii_lowercase())
			.or_insert((now, 0));
		if now.saturating_sub(entry.0) >= self.window_secs {
			*entry = (now, 0);
		}
		if entry.1 >= self.per_window {
			return false;
		}
		entry.1 += 1;
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn allows_up_to_the_limit_then_blocks() {
		let limiter = SendLimiter::new(3, 60);
		assert!(limiter.check("alice", 100));
		assert!(limiter.check("alice", 101));
		assert!(limiter.check("alice", 102));
		// Fourth in the window is blocked.
		assert!(!limiter.check("alice", 103));
	}

	#[test]
	fn window_resets_after_elapsing() {
		let limiter = SendLimiter::new(2, 60);
		assert!(limiter.check("alice", 100));
		assert!(limiter.check("alice", 110));
		assert!(!limiter.check("alice", 120));
		// A new window (>= 60s after the start) resets the count.
		assert!(limiter.check("alice", 160));
	}

	#[test]
	fn accounts_are_independent_and_case_insensitive() {
		let limiter = SendLimiter::new(1, 60);
		assert!(limiter.check("alice@example.org", 100));
		assert!(!limiter.check("ALICE@example.org", 100));
		// A different account has its own budget.
		assert!(limiter.check("bob@example.org", 100));
	}

	#[test]
	fn zero_limit_is_clamped_to_one() {
		let limiter = SendLimiter::new(0, 60);
		assert!(limiter.check("alice", 100));
		assert!(!limiter.check("alice", 101));
	}
}
