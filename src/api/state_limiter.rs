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
	max: u32,
	window_start: std::time::Instant,
	window: std::time::Duration,
}

pub(super) const AUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
pub(super) const AUTH_MAX_FAILURES: u32 = 20;

impl AuthLimiter {
	/// Build a limiter that will roll its window every `window` starting at
	/// `now`. `now` is taken at the call site (typically `Instant::now()`),
	/// not read inside the limiter.
	#[cfg(test)]
	pub(super) fn new(window: std::time::Duration, now: std::time::Instant) -> Self {
		Self::with_max(window, now, AUTH_MAX_FAILURES)
	}

	/// Like [`AuthLimiter::new`] with a failure budget of `max` per window.
	pub(super) fn with_max(window: std::time::Duration, now: std::time::Instant, max: u32) -> Self {
		AuthLimiter {
			failures: 0,
			max,
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
		self.failures >= self.max
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

/// An IPv6 /48 is allowed this many times a client's budget before its failing
/// requests answer `429`: rotating through the /64s of one allocation spends one
/// budget per /64, and this is what stops it.
pub(super) const NET_BUDGET_FACTOR: u32 = 8;

/// Failures across all clients in one window after which failing requests
/// answer `429` instead of `401`. It never blocks a request that presents a
/// valid token; it is the ceiling that still holds when an attacker has more
/// addresses than the tables below can track.
pub(super) const GLOBAL_MAX_FAILURES: u32 = 2_000;

/// Failed argon2 checks of a legacy configured token allowed in one window,
/// from anyone, until the real token has been seen once.
pub(super) const SLOW_CHECKS_PER_WINDOW: u32 = 60;

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
	/// The /48 an IPv6 /64 belongs to.
	V6Net(u64),
}

impl ClientKey {
	fn of(ip: Option<IpAddr>) -> Self {
		match ip {
			None => Self::Unknown,
			Some(IpAddr::V4(v4)) => Self::V4(u32::from(v4)),
			Some(IpAddr::V6(v6)) => Self::V6Prefix((u128::from(v6) >> 64) as u64),
		}
	}

	/// The coarser /48 an IPv6 client also counts under; none for IPv4.
	fn net(ip: Option<IpAddr>) -> Option<Self> {
		match ip {
			Some(IpAddr::V6(v6)) => Some(Self::V6Net((u128::from(v6) >> 80) as u64)),
			_ => None,
		}
	}
}

/// One [`AuthLimiter`] per client. The limit is checked before the token is
/// looked at (a right guess must not get through while the limit holds), and a
/// client that never failed has no entry, so valid traffic costs nothing here.
pub(super) struct ClientLimiters {
	window: Duration,
	clients: HashMap<ClientKey, AuthLimiter>,
	/// One budget per IPv6 /48, [`NET_BUDGET_FACTOR`] times a client's.
	nets: HashMap<ClientKey, AuthLimiter>,
	/// Every failure from anyone, including those from clients that did not
	/// fit in the tables. Consulted only after a request failed, never for
	/// one that presents a valid token, so it cannot lock out a good client.
	global: AuthLimiter,
	/// Argon2 checks of the configured token that failed, from anyone. See
	/// [`ClientLimiters::slow_check_allowed`].
	slow: AuthLimiter,
	last_sweep: Instant,
}

impl ClientLimiters {
	pub(super) fn new(window: Duration) -> Self {
		Self {
			window,
			clients: HashMap::new(),
			nets: HashMap::new(),
			global: AuthLimiter::with_max(window, Instant::now(), GLOBAL_MAX_FAILURES),
			slow: AuthLimiter::with_max(window, Instant::now(), SLOW_CHECKS_PER_WINDOW),
			last_sweep: Instant::now(),
		}
	}

	/// The window length. Test-only.
	#[cfg(test)]
	pub(super) fn window(&self) -> Duration {
		self.window
	}

	/// Replace the global ceiling. Test-only.
	#[cfg(test)]
	pub(super) fn with_global_max(mut self, max: u32) -> Self {
		self.global = AuthLimiter::with_max(self.window, Instant::now(), max);
		self
	}

	/// Whether the client behind `ip` has used up its failures in the window.
	/// This is asked before the token is looked at, so it holds only what one
	/// client did itself: a client without an entry is not limited (a full
	/// table is no reason to refuse someone who never failed), and neither
	/// the /48 nor the global count is consulted, because other people's
	/// failures must not keep a valid token out.
	pub(super) fn is_limited(&mut self, ip: Option<IpAddr>, now: Instant) -> bool {
		self.clients
			.get_mut(&ClientKey::of(ip))
			.is_some_and(|limiter| limiter.is_limited(now))
	}

	/// Whether a request that has just failed should be told to slow down
	/// (`429`) rather than `401`: its IPv6 /48 has spent its budget, or
	/// failures from everyone have passed the global ceiling. Ask only after
	/// the token proved wrong, never for a valid one.
	pub(super) fn limited_after_failure(&mut self, ip: Option<IpAddr>, now: Instant) -> bool {
		self.global.is_limited(now)
			|| ClientKey::net(ip)
				.and_then(|net| self.nets.get_mut(&net))
				.is_some_and(|limiter| limiter.is_limited(now))
	}

	/// Whether another argon2 check of the configured token may run: a legacy
	/// `token_hash` is argon2id, so every wrong token costs one, and anyone
	/// can send wrong tokens. Until the real token has been seen (after which
	/// a wrong one is told apart by a digest and costs nothing), failed checks
	/// share one budget of [`SLOW_CHECKS_PER_WINDOW`] per window.
	pub(super) fn slow_check_allowed(&mut self, now: Instant) -> bool {
		!self.slow.is_limited(now)
	}

	/// Count an argon2 check of the configured token that failed.
	pub(super) fn slow_check_failed(&mut self, now: Instant) {
		self.slow.record_failure(now);
	}

	/// Count one failure for the client behind `ip`, its /48 and the total.
	pub(super) fn record_failure(&mut self, ip: Option<IpAddr>, now: Instant) {
		self.global.record_failure(now);
		if self.clients.len() >= MAX_CLIENTS || self.nets.len() >= MAX_CLIENTS {
			self.sweep(now);
		}
		let window = self.window;
		let count = |table: &mut HashMap<ClientKey, AuthLimiter>, key: ClientKey, max| {
			if let Some(limiter) = table.get_mut(&key) {
				limiter.record_failure(now);
			} else if table.len() < MAX_CLIENTS {
				let mut limiter = AuthLimiter::with_max(window, now, max);
				limiter.record_failure(now);
				table.insert(key, limiter);
			}
		};
		count(&mut self.clients, ClientKey::of(ip), AUTH_MAX_FAILURES);
		if let Some(net) = ClientKey::net(ip) {
			count(
				&mut self.nets,
				net,
				AUTH_MAX_FAILURES.saturating_mul(NET_BUDGET_FACTOR),
			);
		}
	}

	/// Drop entries whose window has passed, at most once a second so a flood
	/// of new clients cannot make every request scan the table.
	fn sweep(&mut self, now: Instant) {
		if now.duration_since(self.last_sweep) < Duration::from_secs(1) {
			return;
		}
		self.last_sweep = now;
		let window = self.window;
		for table in [&mut self.clients, &mut self.nets] {
			table.retain(|_, limiter| now.duration_since(limiter.window_start) < window);
		}
	}

	/// Number of tracked clients. Test-only.
	#[cfg(test)]
	pub(super) fn tracked(&self) -> usize {
		self.clients.len()
	}
}
