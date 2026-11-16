//! The limits on failed bearer sign-ins to the management API, and on the
//! password checks it runs (`[api.limiter]`).
//!
//! A client that fails `max_failures` times in `window_secs` is answered `429`
//! until the window ends. An IPv6 /48 may fail `network_factor` times that,
//! because rotating through its /64s spends one budget each, and failures from
//! everyone together are capped at `global_max_failures`. Argon2 checks of the
//! configured token run `max_concurrent_hashes` at a time, with `hash_queue`
//! more waiting. Every default is the value the server used before these were
//! settings, and each value is bounded on the weak side.

use serde::Deserialize;

use super::bounds::check;

/// Failures per client in a window: 1 to 100 (the weakest).
pub const MAX_FAILURES_BOUNDS: (u32, u32) = (1, 100);
/// Window in seconds: 30 (the weakest) to an hour.
pub const WINDOW_BOUNDS: (u64, u64) = (30, 3600);
/// Multiplier of the budget of an IPv6 /48: 1 to 32.
pub const NETWORK_FACTOR_BOUNDS: (u32, u32) = (1, 32);
/// Failures from all clients in a window: 100 to 20000 (the weakest).
pub const GLOBAL_BOUNDS: (u32, u32) = (100, 20_000);
/// Argon2 checks running at once: 1 to 64.
pub const CONCURRENT_HASHES_BOUNDS: (usize, usize) = (1, 64);
/// Argon2 checks waiting for a turn: 1 to 4096.
pub const HASH_QUEUE_BOUNDS: (usize, usize) = (1, 4096);

/// The `[api.limiter]` configuration section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiLimiter {
	/// Failed bearer attempts one client may make per window. Default 20.
	#[serde(default)]
	pub max_failures: Option<u32>,
	/// The window in seconds. Default 60.
	#[serde(default)]
	pub window_secs: Option<u64>,
	/// How many times `max_failures` an IPv6 /48 may fail. Default 8.
	#[serde(default)]
	pub network_factor: Option<u32>,
	/// Failures across all clients per window after which failing requests
	/// answer `429` instead of `401`. Default 2000.
	#[serde(default)]
	pub global_max_failures: Option<u32>,
	/// Argon2 checks of the configured bearer token that run at once. Default 2.
	#[serde(default)]
	pub max_concurrent_hashes: Option<usize>,
	/// Argon2 checks that may wait for a turn; the next is told `429`. Default 64.
	#[serde(default)]
	pub hash_queue: Option<usize>,
}

impl ApiLimiter {
	/// Default of `max_failures`.
	pub const DEFAULT_MAX_FAILURES: u32 = 20;
	/// Default of `window_secs`.
	pub const DEFAULT_WINDOW_SECS: u64 = 60;
	/// Default of `network_factor`.
	pub const DEFAULT_NETWORK_FACTOR: u32 = 8;
	/// Default of `global_max_failures`.
	pub const DEFAULT_GLOBAL_MAX_FAILURES: u32 = 2_000;
	/// Default of `max_concurrent_hashes`.
	pub const DEFAULT_CONCURRENT_HASHES: usize = 2;
	/// Default of `hash_queue`.
	pub const DEFAULT_HASH_QUEUE: usize = 64;

	/// Failures per client per window.
	pub fn max_failures(&self) -> u32 {
		self.max_failures.unwrap_or(Self::DEFAULT_MAX_FAILURES)
	}

	/// The window in seconds.
	pub fn window_secs(&self) -> u64 {
		self.window_secs.unwrap_or(Self::DEFAULT_WINDOW_SECS)
	}

	/// Multiplier of a client's budget for an IPv6 /48.
	pub fn network_factor(&self) -> u32 {
		self.network_factor.unwrap_or(Self::DEFAULT_NETWORK_FACTOR)
	}

	/// Failures across all clients per window.
	pub fn global_max_failures(&self) -> u32 {
		self.global_max_failures
			.unwrap_or(Self::DEFAULT_GLOBAL_MAX_FAILURES)
	}

	/// Argon2 checks that run at once.
	pub fn max_concurrent_hashes(&self) -> usize {
		self.max_concurrent_hashes
			.unwrap_or(Self::DEFAULT_CONCURRENT_HASHES)
	}

	/// Argon2 checks that may wait for a turn.
	pub fn hash_queue(&self) -> usize {
		self.hash_queue.unwrap_or(Self::DEFAULT_HASH_QUEUE)
	}

	/// Refuse a value outside its bounds.
	pub fn validate(&self) -> Result<(), String> {
		check(
			"[api.limiter] max_failures",
			self.max_failures,
			MAX_FAILURES_BOUNDS,
		)?;
		check("[api.limiter] window_secs", self.window_secs, WINDOW_BOUNDS)?;
		check(
			"[api.limiter] network_factor",
			self.network_factor,
			NETWORK_FACTOR_BOUNDS,
		)?;
		check(
			"[api.limiter] global_max_failures",
			self.global_max_failures,
			GLOBAL_BOUNDS,
		)?;
		check(
			"[api.limiter] max_concurrent_hashes",
			self.max_concurrent_hashes,
			CONCURRENT_HASHES_BOUNDS,
		)?;
		check(
			"[api.limiter] hash_queue",
			self.hash_queue,
			HASH_QUEUE_BOUNDS,
		)?;
		Ok(())
	}
}

#[cfg(test)]
mod tests;
