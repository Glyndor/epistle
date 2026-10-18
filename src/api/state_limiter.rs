//! The bearer-token failure limiter: a sliding window per client, so one
//! client's wrong tokens cannot lock everyone else out of the API.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Sliding-window failure counter. Prevents brute force on the bearer token.
///
/// The clock and the window length are passed in by the caller so the limiter
/// does not read `Instant::now()` itself. That makes the limiter's window
/// logic deterministic from the tests' point of view (no sleeping, no
/// flake under a loaded parallel run) and lets production code share one
/// `now` value across the read and the record in the same request.
pub(super) struct AuthLimiter {
	failures: u32,
	window_start: std::time::Instant,
	window: std::time::Duration,
}

pub(super) const AUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
pub(super) const AUTH_MAX_FAILURES: u32 = 20;

impl AuthLimiter {
	/// Build a limiter that will roll its window every `window` starting at
	/// `now`. `now` is taken at the call site (typically `Instant::now()`),
	/// not read inside the limiter.
	pub(super) fn new(window: std::time::Duration, now: std::time::Instant) -> Self {
		AuthLimiter {
			failures: 0,
			window_start: now,
			window,
		}
	}

	/// Roll the window if `now` is at or past its end, then report whether
	/// the failure count has reached the threshold.
	pub(super) fn is_limited(&mut self, now: std::time::Instant) -> bool {
		if now.duration_since(self.window_start) >= self.window {
			self.failures = 0;
			self.window_start = now;
		}
		self.failures >= AUTH_MAX_FAILURES
	}

	/// Roll the window if `now` is at or past its end, then record a new
	/// failure against the current window.
	pub(super) fn record_failure(&mut self, now: std::time::Instant) {
		if now.duration_since(self.window_start) >= self.window {
			self.failures = 0;
			self.window_start = now;
		}
		self.failures = self.failures.saturating_add(1);
	}

	/// Clear the count and start a fresh window at `now`.
	#[cfg(test)]
	pub(super) fn reset(&mut self, now: std::time::Instant) {
		self.failures = 0;
		self.window_start = now;
	}
}

/// Most clients tracked at once. A client is only tracked after a failure, and
/// its entry is dropped when its window passes, so this bounds memory under a
/// flood from many addresses (about 100,000 entries, a few megabytes).
pub(super) const MAX_CLIENTS: usize = 100_000;

/// How a request's client is told apart from others: an IPv4 address, an IPv6
/// /64 (one host there controls the whole /64), or "unknown" when the peer
/// address is not available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ClientKey {
	Unknown,
	V4(u32),
	V6Prefix(u64),
}

impl ClientKey {
	fn of(ip: Option<IpAddr>) -> Self {
		match ip {
			None => Self::Unknown,
			Some(IpAddr::V4(v4)) => Self::V4(u32::from(v4)),
			Some(IpAddr::V6(v6)) => Self::V6Prefix((u128::from(v6) >> 64) as u64),
		}
	}
}

/// One [`AuthLimiter`] per client. The limit is checked before the token is
/// looked at (a right guess must not get through while the limit holds), and a
/// client that never failed has no entry, so valid traffic costs nothing here.
pub(super) struct ClientLimiters {
	window: Duration,
	clients: HashMap<ClientKey, AuthLimiter>,
	/// Failures from clients that did not fit in `clients`. While the table is
	/// full they share this one budget, and a client with no entry is held to
	/// it, so a flood from more addresses than the table holds is limited as a
	/// group instead of not at all.
	overflow: AuthLimiter,
	last_sweep: Instant,
}

impl ClientLimiters {
	pub(super) fn new(window: Duration) -> Self {
		Self {
			window,
			clients: HashMap::new(),
			overflow: AuthLimiter::new(window, Instant::now()),
			last_sweep: Instant::now(),
		}
	}

	/// Whether the client behind `ip` has used up its failures in the window.
	pub(super) fn is_limited(&mut self, ip: Option<IpAddr>, now: Instant) -> bool {
		let key = ClientKey::of(ip);
		if let Some(limiter) = self.clients.get_mut(&key) {
			return limiter.is_limited(now);
		}
		self.clients.len() >= MAX_CLIENTS && self.overflow.is_limited(now)
	}

	/// Count one failure for the client behind `ip`.
	pub(super) fn record_failure(&mut self, ip: Option<IpAddr>, now: Instant) {
		let key = ClientKey::of(ip);
		if let Some(limiter) = self.clients.get_mut(&key) {
			limiter.record_failure(now);
			return;
		}
		if self.clients.len() >= MAX_CLIENTS {
			self.sweep(now);
		}
		if self.clients.len() < MAX_CLIENTS {
			let mut limiter = AuthLimiter::new(self.window, now);
			limiter.record_failure(now);
			self.clients.insert(key, limiter);
		} else {
			self.overflow.record_failure(now);
		}
	}

	/// Forget the failures of the client behind `ip` after it presented a
	/// valid token. Other clients keep theirs: a success elsewhere gives a
	/// flooder nothing back.
	pub(super) fn reset(&mut self, ip: Option<IpAddr>) {
		self.clients.remove(&ClientKey::of(ip));
	}

	/// Drop entries whose window has passed, at most once a second so a flood
	/// of new clients cannot make every request scan the table.
	fn sweep(&mut self, now: Instant) {
		if now.duration_since(self.last_sweep) < Duration::from_secs(1) {
			return;
		}
		self.last_sweep = now;
		let window = self.window;
		self.clients
			.retain(|_, limiter| now.duration_since(limiter.window_start) < window);
	}

	/// Number of tracked clients. Test-only.
	#[cfg(test)]
	pub(super) fn tracked(&self) -> usize {
		self.clients.len()
	}
}
