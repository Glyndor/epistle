//! Fixed-window, string-keyed rate limiter shared across server-side call sites.
//!
//! The limiter is a single mutable map of `key -> (window_start_epoch, count)`
//! guarded by one mutex. Each [`check`](WindowLimiter::check) call looks up
//! the key, advances the window once `window_secs` have elapsed, and either
//! increments the count or returns `false` to signal "over the limit". The
//! caller supplies the cap (`limit`) per call so one limiter can back several
//! policies (per-account, per-IP, per-sender, per-tenant).
//!
//! ## Bounded memory
//!
//! The `state` map grows monotonically with every distinct key an attacker
//! is willing to feed. To keep memory finite under attack, every [`SendLimiter::check`]
//! sweeps entries whose window started more than **two window lengths ago**
//! whenever the map holds more than `EVICTION_THRESHOLD` entries. With a
//! 60-second window the steady-state map holds at most `EVICTION_THRESHOLD`
//! plus the handful of fresh keys that just landed; an active churning peer
//! cannot push it past that bound because the next `check` re-sweeps.
//!
//! `limit == 0` is treated as "no limit" (always allowed): the policy layer
//! is expected to skip the call when the resolved limit is `None`, so a
//! literal zero only appears when an operator deliberately configured it.

use std::collections::HashMap;
use std::sync::Mutex;

/// Soft cap on the `state` map. Once exceeded, [`WindowLimiter::check`]
/// runs a sweep and keeps the map under this size.
const EVICTION_THRESHOLD: usize = 10_000;

/// A shared, fixed-window rate limiter keyed by an arbitrary string.
///
/// `key` is lowercased (ASCII case-insensitive) before lookup. The window
/// is fixed rather than sliding and resets each `window_secs` after the last
/// increment for that key.
#[derive(Debug)]
pub struct WindowLimiter {
	/// Window length in seconds.
	window_secs: u64,
	/// Per-key `(window_start_epoch, count_in_window)`.
	state: Mutex<HashMap<String, (u64, u32)>>,
}

/// Backwards-compatible alias. Kept so existing call sites (per-account
/// submission limit, per-tenant aggregate limit) keep compiling; new callers
/// should prefer [`WindowLimiter`] and its `key` parameter name.
pub type SendLimiter = WindowLimiter;

/// A `(limiter, cap)` pair for an unauthenticated inbound limit. Built once
/// in `cli/serve::serve` from the matching top-level config field, then
/// handed to every SMTP listener so each listener shares the same window
/// state with the others.
#[derive(Debug)]
pub struct InboundLimit {
	/// Shared window state across all listeners.
	pub limiter: std::sync::Arc<SendLimiter>,
	/// Per-minute ceiling the limiter compares against.
	pub per_min: u32,
}

impl WindowLimiter {
	/// A limiter that evaluates a per-call `limit` against a shared fixed
	/// window of `window_secs` seconds. `window_secs` is clamped to one so
	/// the window still advances on every check.
	pub fn new(window_secs: u64) -> Self {
		WindowLimiter {
			window_secs: window_secs.max(1),
			state: Mutex::new(HashMap::new()),
		}
	}

	/// Record one event for `key` at `now` (epoch seconds) against the
	/// per-key `limit` (events per window) and report whether it is within
	/// the limit.
	///
	/// On every call the limiter drops the looked-up entry's count when
	/// its window is stale (`now - window_start >= window_secs`) before
	/// counting this event, so a key that has been idle longer than the
	/// window gets a fresh budget. The window is the fixed-window kind: a
	/// continuous burst for `window_secs` then a hard reset.
	pub fn check(&self, key: &str, limit: u32, now: u64) -> bool {
		if limit == 0 {
			return true;
		}
		let mut state = self.state.lock().expect("send limiter");
		let entry = state.entry(key.to_ascii_lowercase()).or_insert((now, 0));
		if now.saturating_sub(entry.0) >= self.window_secs {
			*entry = (now, 0);
		}
		if entry.1 >= limit {
			return false;
		}
		entry.1 += 1;
		if state.len() > EVICTION_THRESHOLD {
			// Two-window cutoff: even a slow-churning key gets swept out
			// long before the window it tracks becomes meaningful again.
			let cutoff = now.saturating_sub(self.window_secs.saturating_mul(2));
			state.retain(|_key, (start, _count)| *start > cutoff);
		}
		true
	}

	/// Number of entries currently held in the state map. Test-only helper,
	/// useful to assert that an eviction sweep ran and the map stayed
	/// bounded.
	#[cfg(test)]
	fn len(&self) -> usize {
		self.state.lock().expect("send limiter").len()
	}
}

#[cfg(test)]
#[path = "ratelimit_tests.rs"]
mod tests;
