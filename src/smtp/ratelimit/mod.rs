//! Fixed-window, string-keyed rate limiter shared across server-side call sites.
//!
//! The limiter is a single mutable map of `key -> (window_start_epoch, count)`
//! guarded by one mutex. Each [`check_n`](WindowLimiter::check_n) call looks
//! up the key, starts a new window once `window_secs` have elapsed, and either
//! adds the charge or returns `false` to signal "over the limit". A refused
//! call charges nothing. The caller supplies the cap (`limit`) per call so
//! one limiter can back several policies (per-account, per-IP, per-sender,
//! per-tenant).
//!
//! ## Bounded memory and constant per-call work
//!
//! A key already in the map is handled in place, so an active sender keeps
//! its budget however full the map is. The `windows` queue records
//! `(key, window_start)` in the order windows began, so its first live
//! record is the entry whose window is the oldest. Records whose window has
//! since been replaced are skipped, and the queue is compacted once it holds
//! twice the larger of the map and [`MAX_ENTRIES`], so each call does O(1)
//! amortized work.
//!
//! What happens to an unseen key once the map holds [`MAX_ENTRIES`] keys
//! depends on who chooses the keys:
//!
//! - [`WindowLimiter::new`], for the inbound limits, whose keys come from
//!   the network (client IPs, envelope senders). The map is capped: the
//!   oldest window makes room, running or not, because refusing would let a
//!   flood of fresh keys defer every new sender.
//! - [`WindowLimiter::for_authenticated_keys`], for the submission limits,
//!   whose keys are accounts and tenants the server authenticated, a set the
//!   directory bounds. A new key is always admitted and a running window is
//!   never dropped for it: refusing would lock every account that had not
//!   sent yet out of submission once [`MAX_ENTRIES`] accounts had sent in
//!   one window, and evicting would reset a sender's window. Past the cap
//!   each new key still drops the oldest window if it is over, so the map
//!   stays near the number of accounts sending inside one window.
//!
//! `limit == 0` is treated as "no limit" (always allowed): the policy layer
//! is expected to skip the call when the resolved limit is `None`, so a
//! literal zero only appears when an operator deliberately configured it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

/// Size of the `entries` map past which an unseen key makes room: by
/// evicting the oldest window ([`WindowLimiter::new`]), or by dropping it
/// only when it is over ([`WindowLimiter::for_authenticated_keys`]).
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
	/// The keys are authenticated accounts and tenants, bounded by the
	/// directory: past the cap, a new key is admitted without evicting a
	/// running window. `false` caps the map by evicting the oldest window.
	authenticated_keys: bool,
	/// The shared mutable map plus the window-order queue. Both are
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
	/// `(key, window_start)` for every window started, oldest first. A
	/// record is live while `entries[key]` still has that window start;
	/// the others are skipped (and dropped) when they reach the head.
	windows: VecDeque<(String, u64)>,
	/// Test-only counter of how many records the eviction walk visited
	/// across every `check` call so a regression test can assert the
	/// per-call work stays bounded when the map sits at the cap.
	#[cfg(test)]
	scan_count: u64,
}

impl StateInner {
	/// Record that `key` started a window at `start`, compacting the queue
	/// when dead records make it twice the size of the map (or of the cap,
	/// when the map is smaller). A compaction is O(queue) and leaves one
	/// record per entry, so the next one follows at least as many pushes:
	/// O(1) amortized.
	fn record_window(&mut self, key: String, start: u64) {
		self.windows.push_back((key, start));
		if self.windows.len() > 2 * self.entries.len().max(MAX_ENTRIES) {
			let entries = &self.entries;
			self.windows
				.retain(|(key, start)| entries.get(key).is_some_and(|entry| entry.0 == *start));
		}
	}

	/// Free one slot for an unseen key. Drops the entry whose window is
	/// the oldest when that window is over, or when `evict_active` allows
	/// dropping a running one; `false` when no slot can be freed.
	fn free_slot(&mut self, now: u64, window_secs: u64, evict_active: bool) -> bool {
		loop {
			let Some((key, start)) = self.windows.front() else {
				// The queue is empty but the map is full: an entry
				// escaped its record. Free nothing rather than panic.
				return false;
			};
			#[cfg(test)]
			{
				self.scan_count += 1;
			}
			let live = self.entries.get(key).is_some_and(|entry| entry.0 == *start);
			if !live {
				self.windows.pop_front();
				continue;
			}
			if now.saturating_sub(*start) < window_secs && !evict_active {
				return false;
			}
			let (key, _) = self.windows.pop_front().expect("front checked above");
			self.entries.remove(&key);
			return true;
		}
	}
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
	/// the window still advances on every check. With the map full of
	/// running windows an unseen key evicts the oldest one: the right
	/// choice when keys come from the network (client IPs, envelope
	/// senders), where refusing would let a flood defer every new sender.
	pub fn new(window_secs: u64) -> Self {
		WindowLimiter {
			window_secs: window_secs.max(1),
			authenticated_keys: false,
			state: Mutex::new(StateInner::default()),
		}
	}

	/// Like [`new`](Self::new), for keys the server authenticated
	/// (accounts and tenants), whose number the directory bounds. A new key
	/// is always admitted and never evicts a running window, so no amount
	/// of traffic resets a sender's window, and no number of accounts
	/// sending at once locks the others out. Windows that are over still
	/// make room, which keeps the map near the number of keys active in
	/// one window.
	pub fn for_authenticated_keys(window_secs: u64) -> Self {
		WindowLimiter {
			authenticated_keys: true,
			..Self::new(window_secs)
		}
	}

	/// Record one event for `key` at `now` (epoch seconds) against the
	/// per-key `limit` (events per window) and report whether it is within
	/// the limit. Same as [`check_n`](Self::check_n) with a count of one.
	pub fn check(&self, key: &str, limit: u32, now: u64) -> bool {
		self.check_n(key, 1, limit, now)
	}

	/// Record `count` events for `key` at `now` (epoch seconds) against
	/// the per-key `limit` and report whether every event fits. Used by
	/// the per-recipient submission limits where one submission charges
	/// one unit per recipient, so a 100-recipient message costs 100
	/// units; a bounce with no recipients costs 0.
	///
	/// All or nothing: a call that would take the window past `limit`
	/// charges nothing and returns `false`, including the first call of a
	/// window. `count == 0` is a no-op that returns `true`. A window older
	/// than `window_secs` starts over at `now` before the charge.
	pub fn check_n(&self, key: &str, count: u32, limit: u32, now: u64) -> bool {
		if limit == 0 || count == 0 {
			return true;
		}
		let key_lc = key.to_ascii_lowercase();
		let mut state = self.state.lock().expect("send limiter");
		if let Some(entry) = state.entries.get_mut(&key_lc) {
			let restart = now.saturating_sub(entry.0) >= self.window_secs;
			let used = if restart { 0 } else { entry.1 };
			if used.saturating_add(count) > limit {
				return false;
			}
			if restart {
				*entry = (now, count);
				state.record_window(key_lc, now);
			} else {
				entry.1 = used + count;
			}
			return true;
		}
		if count > limit {
			return false;
		}
		if state.entries.len() >= MAX_ENTRIES {
			let freed = state.free_slot(now, self.window_secs, !self.authenticated_keys);
			// The network-keyed map is capped; an authenticated key is
			// admitted whether or not a slot was freed.
			if !freed && !self.authenticated_keys {
				return false;
			}
		}
		state.entries.insert(key_lc.clone(), (now, count));
		state.record_window(key_lc, now);
		true
	}

	/// Whether `count` more events for `key` would fit at `now`, without
	/// charging them. The SMTP path asks this at `MAIL FROM` so a sender
	/// already at its cap is refused before it sends the message; the
	/// charge itself happens once the message is accepted.
	pub fn has_room(&self, key: &str, count: u32, limit: u32, now: u64) -> bool {
		if limit == 0 || count == 0 {
			return true;
		}
		let state = self.state.lock().expect("send limiter");
		let used = match state.entries.get(&key.to_ascii_lowercase()) {
			Some(&(start, used)) if now.saturating_sub(start) < self.window_secs => used,
			_ => 0,
		};
		used.saturating_add(count) <= limit
	}

	/// Give back `count` events charged for `key` at `now` by a
	/// [`check_n`](Self::check_n) whose message was then not accepted.
	/// Only the window that took the charge is credited: once a newer
	/// window has started for the key, the refund is dropped, so it can
	/// never raise a later window's budget.
	pub fn refund(&self, key: &str, count: u32, now: u64) {
		let mut state = self.state.lock().expect("send limiter");
		if let Some(entry) = state.entries.get_mut(&key.to_ascii_lowercase())
			&& entry.0 <= now
			&& now.saturating_sub(entry.0) < self.window_secs
		{
			entry.1 = entry.1.saturating_sub(count);
		}
	}

	/// Number of entries currently held in the state map. Test-only helper,
	/// useful to assert that an eviction sweep ran and the map stayed
	/// bounded.
	#[cfg(test)]
	fn len(&self) -> usize {
		self.state.lock().expect("send limiter").entries.len()
	}

	/// Total number of records the eviction walk has visited across every
	/// `check` call. Test-only counter used to assert the per-call work
	/// stays bounded: each record is visited once before it is dropped, so
	/// the work is O(1) amortized.
	#[cfg(test)]
	fn scan_count(&self) -> u64 {
		self.state.lock().expect("send limiter").scan_count
	}

	/// Number of window records queued. Test-only, to assert the queue
	/// stays bounded however often keys start new windows.
	#[cfg(test)]
	fn window_records(&self) -> usize {
		self.state.lock().expect("send limiter").windows.len()
	}
}

#[cfg(test)]
mod tests;
