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
//! The `state` map is capped at [`MAX_ENTRIES`] entries. A key already in
//! the map is handled in place (its window is reset if stale and its count
//! is incremented) so an active sender keeps its budget while the map sits
//! at the cap. A key that is not in the map is admitted only when there is
//! room; when the cap is reached the check performs an incremental expiry
//! pass that scans at most `EVICTION_SCAN_BUDGET` entries and removes the
//! stale ones, then admits the new key if the eviction freed a slot. If the
//! map is still full after the pass, the unseen key is refused: returning
//! `false` blocks the message without ever dropping a live entry.
//!
//! `limit == 0` is treated as "no limit" (always allowed): the policy layer
//! is expected to skip the call when the resolved limit is `None`, so a
//! literal zero only appears when an operator deliberately configured it.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Hard cap on the `state` map. Once [`MAX_ENTRIES`] distinct keys are
/// tracked, an unseen key is refused unless the incremental expiry pass
/// makes room first.
pub const MAX_ENTRIES: usize = 10_000;

/// Maximum number of map entries the incremental expiry pass scans per
/// `check` call. Each scan entry is one O(log n) lookup on the [`BTreeMap`]
/// plus a window-start comparison, so a single `check` does at most this
/// many lookups of stale `window_start` values beyond the active-key
/// lookup. Bounded so a fully-saturated limiter cannot do O(map_size)
/// work per call.
const EVICTION_SCAN_BUDGET: usize = 64;

/// A shared, fixed-window rate limiter keyed by an arbitrary string.
///
/// `key` is lowercased (ASCII case-insensitive) before lookup. The window
/// is fixed rather than sliding and resets each `window_secs` after the last
/// increment for that key.
#[derive(Debug)]
pub struct WindowLimiter {
	/// Window length in seconds.
	window_secs: u64,
	/// Per-key `(window_start_epoch, count_in_window)`. A [`BTreeMap`] is
	/// used so the incremental expiry pass has a deterministic iteration
	/// order; the cursor below advances across calls and a renewing entry
	/// at the front of the iteration cannot starve the entries behind it.
	state: Mutex<BTreeMap<String, (u64, u32)>>,
	/// Last key the incremental expiry pass examined. The next pass scans
	/// the keys strictly greater than this one and wraps around to the
	/// smallest key when the end is reached. Without a persistent cursor
	/// every call would restart from the smallest key and a renewing
	/// entry at the front of the iteration would lock the rest of the
	/// map out of the eviction pass forever.
	cursor: Mutex<Option<String>>,
	/// Test-only counter of map entries the incremental expiry pass has
	/// scanned. Lets a regression test assert that the per-call work stays
	/// bounded when the map sits at the cap.
	#[cfg(test)]
	scan_count: Mutex<u64>,
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
			state: Mutex::new(BTreeMap::new()),
			cursor: Mutex::new(None),
			#[cfg(test)]
			scan_count: Mutex::new(0),
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
	///
	/// The map size is capped at [`MAX_ENTRIES`]. When a brand-new key
	/// would push the map past the cap, the call performs a bounded
	/// incremental expiry pass and admits the key only if a slot was
	/// freed. The active-key path (the entry is already present) never
	/// evicts; an existing sender keeps its budget through every call
	/// that hits a full map.
	pub fn check(&self, key: &str, limit: u32, now: u64) -> bool {
		if limit == 0 {
			return true;
		}
		let key_lc = key.to_ascii_lowercase();
		let mut state = self.state.lock().expect("send limiter");
		if let Some(entry) = state.get_mut(&key_lc) {
			if now.saturating_sub(entry.0) >= self.window_secs {
				*entry = (now, 0);
			}
			if entry.1 >= limit {
				return false;
			}
			entry.1 += 1;
			return true;
		}
		if state.len() >= MAX_ENTRIES {
			// Unseen key at the cap: do an incremental expiry pass that
			// scans at most EVICTION_SCAN_BUDGET entries, drop the ones
			// whose window started more than two window-lengths ago, and
			// admit the new key only if a slot was freed. The active-key
			// path above never reaches this branch, so live budgets are
			// preserved even when the map is saturated. The cursor below
			// makes the pass advance across calls: a renewing entry at
			// the front of the iteration cannot starve the entries behind
			// it because the next call resumes strictly after the last
			// entry this one examined, then wraps back to the smallest
			// key once the end is reached.
			let cutoff = now.saturating_sub(self.window_secs.saturating_mul(2));
			let cursor = self.cursor.lock().expect("cursor").clone();
			let keys: Vec<String> = state.keys().cloned().collect();
			let keys_len = keys.len();
			let start_idx = match cursor.as_ref() {
				Some(c) => keys.iter().position(|k| k > c).unwrap_or(0),
				None => 0,
			};
			let mut stale: Vec<String> = Vec::new();
			let mut last_key: Option<String> = None;
			#[cfg(test)]
			let mut scanned: u64 = 0;
			if keys_len > 0 {
				for offset in 0..EVICTION_SCAN_BUDGET {
					let idx = (start_idx + offset) % keys_len;
					let key = &keys[idx];
					let (start, _) = state.get(key).expect("key present in state");
					if *start <= cutoff {
						stale.push(key.clone());
					}
					#[cfg(test)]
					{
						scanned += 1;
					}
					last_key = Some(key.clone());
				}
			}
			// Update the cursor so the next call resumes after the last
			// entry examined. The advance is what defeats the starvation
			// case: a renewing entry at the front of the iteration is
			// left behind on the next call.
			if let Some(last) = last_key {
				*self.cursor.lock().expect("cursor") = Some(last);
			} else {
				*self.cursor.lock().expect("cursor") = None;
			}
			for k in &stale {
				state.remove(k);
			}
			#[cfg(test)]
			{
				*self.scan_count.lock().expect("scan count") += scanned;
			}
			if state.len() >= MAX_ENTRIES {
				return false;
			}
		}
		state.insert(key_lc, (now, 1));
		true
	}

	/// Number of entries currently held in the state map. Test-only helper,
	/// useful to assert that an eviction sweep ran and the map stayed
	/// bounded.
	#[cfg(test)]
	fn len(&self) -> usize {
		self.state.lock().expect("send limiter").len()
	}

	/// Total number of map entries the incremental expiry pass has scanned
	/// across every `check` call so far. Test-only counter used to assert
	/// the per-call work stays bounded.
	#[cfg(test)]
	fn scan_count(&self) -> u64 {
		*self.scan_count.lock().expect("scan count")
	}
}

#[cfg(test)]
#[path = "ratelimit_tests.rs"]
mod tests;
