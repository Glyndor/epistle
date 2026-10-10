//! Fixed-window, string-keyed rate limiter shared across server-side call sites.
//!
//! The limiter is a single mutable map of `key -> (window_start_epoch, count)`
//! guarded by one mutex. Each [`check`](WindowLimiter::check) call looks up
//! the key, advances the window once `window_secs` have elapsed, and either
//! increments the count or returns `false` to signal "over the limit". The
//! caller supplies the cap (`limit`) per call so one limiter can back several
//! policies (per-account, per-IP, per-sender, per-tenant).
//!
//! ## Bounded memory and constant per-call work
//!
//! The `state` map is capped at [`MAX_ENTRIES`] entries. A key already in
//! the map is handled in place (its window is reset if stale and its count
//! is incremented) so an active sender keeps its budget while the map sits
//! at the cap. A key that is not in the map is admitted by evicting the
//! oldest entry when the cap is full: an `insertion`-ordered [`VecDeque`]
//! tracks the order in which keys first appeared in the map, and the
//! head is lazily popped (skipping keys that have already been removed or
//! never existed) to evict the entry whose window started earliest.
//! O(1) amortized.
//!
//! `limit == 0` is treated as "no limit" (always allowed): the policy layer
//! is expected to skip the call when the resolved limit is `None`, so a
//! literal zero only appears when an operator deliberately configured it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

/// Hard cap on the `state` map. Once [`MAX_ENTRIES`] distinct keys are
/// tracked, an unseen key evicts the oldest entry (insertion order) and
/// is admitted; a live sender keeps its budget through every call that
/// hits a full map.
pub const MAX_ENTRIES: usize = 10_000;

/// A shared, fixed-window rate limiter keyed by an arbitrary string.
///
/// `key` is lowercased (ASCII case-insensitive) before lookup. The window
/// is fixed rather than sliding and resets each `window_secs` after the last
/// increment for that key.
#[derive(Debug)]
pub struct WindowLimiter {
	/// Window length in seconds.
	window_secs: u64,
	/// The shared mutable map plus the insertion-order queue. Both are
	/// guarded by a single mutex so `check` cannot deadlock with itself
	/// across the two structures.
	state: Mutex<StateInner>,
}

/// Internal state of [`WindowLimiter`] held under one mutex.
#[derive(Debug, Default)]
struct StateInner {
	/// Per-key `(window_start_epoch, count_in_window)`. A [`BTreeMap`] is
	/// used so the in-place active-key path and the membership test
	/// during eviction are O(log n).
	entries: BTreeMap<String, (u64, u32)>,
	/// Insertion order of the keys currently in `entries` (plus any
	/// stale entries that have already been removed from `entries`,
	/// which the eviction walk skips). The head holds the entry whose
	/// window started earliest; popping the head is the eviction.
	insertion: VecDeque<String>,
	/// Test-only counter of how many entries the eviction walk visited
	/// across every `check` call so a regression test can assert the
	/// per-call work stays bounded when the map sits at the cap.
	#[cfg(test)]
	scan_count: u64,
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
			state: Mutex::new(StateInner::default()),
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
	/// The map size is capped at [`MAX_ENTRIES`]. A new key always fits,
	/// because an unseen key at the cap evicts the oldest entry in
	/// insertion order to make room: the head of `insertion` is popped
	/// (skipping keys that no longer live in `entries`) and the matching
	/// entry is removed, then the new key is inserted. The active-key
	/// path never evicts; an existing sender keeps its budget through
	/// every call that hits a full map.
	pub fn check(&self, key: &str, limit: u32, now: u64) -> bool {
		if limit == 0 {
			return true;
		}
		let key_lc = key.to_ascii_lowercase();
		let mut state = self.state.lock().expect("send limiter");
		// Active-key path: the entry is already present. Its window may
		// have elapsed, in which case the count resets to 0; we never
		// evict here, so a live budget survives a saturated map.
		if let Some(entry) = state.entries.get_mut(&key_lc) {
			if now.saturating_sub(entry.0) >= self.window_secs {
				*entry = (now, 0);
			}
			if entry.1 >= limit {
				return false;
			}
			entry.1 += 1;
			return true;
		}
		// Unseen key. If the cap is full, evict the oldest entry to make
		// room. The head of `insertion` is the oldest live entry; stale
		// entries (whose key was already removed) are skipped lazily.
		// Every visit, including skips of stale entries and the chosen
		// eviction, increments the test-only scan counter so the bound
		// regression can observe the per-call work.
		if state.entries.len() >= MAX_ENTRIES {
			loop {
				let Some(front) = state.insertion.front().cloned() else {
					// The queue is empty but the map is full: an entry
					// escaped removal. Treat the inconsistency as a
					// refusal rather than panicking; the next call that
					// touches the same key recovers.
					return false;
				};
				#[cfg(test)]
				{
					state.scan_count += 1;
				}
				if state.entries.contains_key(&front) {
					state.entries.remove(&front);
					state.insertion.pop_front();
					break;
				}
				state.insertion.pop_front();
			}
		}
		state.entries.insert(key_lc.clone(), (now, 1));
		state.insertion.push_back(key_lc);
		true
	}

	/// Number of entries currently held in the state map. Test-only helper,
	/// useful to assert that an eviction sweep ran and the map stayed
	/// bounded.
	#[cfg(test)]
	fn len(&self) -> usize {
		self.state.lock().expect("send limiter").entries.len()
	}

	/// Total number of entries the eviction walk has visited across every
	/// `check` call. Test-only counter used to assert the per-call work
	/// stays bounded. With the insertion-ordered eviction, each call does
	/// O(1) amortized work (a single pop_front, or a few when stale entries
	/// have accumulated) so the bound holds trivially.
	#[cfg(test)]
	fn scan_count(&self) -> u64 {
		self.state.lock().expect("send limiter").scan_count
	}
}

#[cfg(test)]
#[path = "ratelimit_tests.rs"]
mod tests;
