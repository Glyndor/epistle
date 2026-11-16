//! The sign-in ban policy (`[bans]`).
//!
//! A ban follows failed sign-ins: `threshold` failures inside `window_secs`
//! ban the client (or the account and client pair) for `base_secs`, each next
//! ban of the same subject doubles that up to `max_secs`, and the account
//! subject needs `account_threshold_factor` times the failures, so one client
//! alone cannot ban an account. Every default is the value the server used
//! before these were settings.
//!
//! Each value has a limit on the weak side that the loader enforces, because
//! the ban is the protection: more tolerated failures, a shorter window or a
//! shorter ban make guessing cheaper. The strong side is bounded only by what
//! is usable. The bounds are listed in `docs/configuration.md`.

use serde::Deserialize;

use super::bounds::check;
use crate::antispam::bans::BanPolicy;

/// Failures inside the window that fire a ban: at least 2 (a single typo
/// bans nobody), at most 20 (the weakest the loader allows).
pub const THRESHOLD_BOUNDS: (u32, u32) = (2, 20);
/// Rolling window, in seconds: at least 5 minutes (the weakest), at most a day.
pub const WINDOW_BOUNDS: (u64, u64) = (300, 86_400);
/// First ban length, in seconds: at least 5 minutes (the weakest), at most a day.
pub const BASE_BOUNDS: (u64, u64) = (300, 86_400);
/// Longest ban length, in seconds: at least an hour (the weakest), at most 30 days.
pub const MAX_BOUNDS: (u64, u64) = (3600, 2_592_000);
/// Multiplier of the threshold for an account subject: at least 2, so one
/// client cannot reach it alone, and at most 8.
pub const ACCOUNT_FACTOR_BOUNDS: (u32, u32) = (2, 8);
/// Networks kept per account as known: 1 to 256.
pub const KNOWN_NETWORKS_BOUNDS: (u32, u32) = (1, 256);

/// The `[bans]` configuration section. Absent keys keep the defaults of
/// [`BanPolicy`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bans {
	/// Failures inside `window_secs` that fire a ban. Default 5.
	#[serde(default)]
	pub threshold: Option<u32>,
	/// Rolling window in seconds. Default 900.
	#[serde(default)]
	pub window_secs: Option<u64>,
	/// Length in seconds of the first ban; each next one doubles. Default 900.
	#[serde(default)]
	pub base_secs: Option<u64>,
	/// Longest ban in seconds. Default 86400.
	#[serde(default)]
	pub max_secs: Option<u64>,
	/// How many times `threshold` the account subject needs. Default 4.
	#[serde(default)]
	pub account_threshold_factor: Option<u32>,
	/// Networks kept per account on the known-network list. Default 32.
	#[serde(default)]
	pub known_network_max_per_account: Option<u32>,
}

impl Bans {
	/// Refuse a value outside its bounds, and a `max_secs` below `base_secs`.
	pub fn validate(&self) -> Result<(), String> {
		check("[bans] threshold", self.threshold, THRESHOLD_BOUNDS)?;
		check("[bans] window_secs", self.window_secs, WINDOW_BOUNDS)?;
		check("[bans] base_secs", self.base_secs, BASE_BOUNDS)?;
		check("[bans] max_secs", self.max_secs, MAX_BOUNDS)?;
		check(
			"[bans] account_threshold_factor",
			self.account_threshold_factor,
			ACCOUNT_FACTOR_BOUNDS,
		)?;
		check(
			"[bans] known_network_max_per_account",
			self.known_network_max_per_account,
			KNOWN_NETWORKS_BOUNDS,
		)?;
		let policy = self.policy(BanPolicy::default());
		if policy.max_secs < policy.base_secs {
			return Err(format!(
				"[bans] max_secs ({}) must not be shorter than base_secs ({})",
				policy.max_secs, policy.base_secs
			));
		}
		Ok(())
	}

	/// `base` with every value this section sets laid over it.
	pub fn policy(&self, base: BanPolicy) -> BanPolicy {
		BanPolicy {
			threshold: self.threshold.unwrap_or(base.threshold),
			window_secs: self.window_secs.unwrap_or(base.window_secs),
			base_secs: self.base_secs.unwrap_or(base.base_secs),
			max_secs: self.max_secs.unwrap_or(base.max_secs),
			account_threshold_factor: self
				.account_threshold_factor
				.unwrap_or(base.account_threshold_factor),
			known_network_max_per_account: self
				.known_network_max_per_account
				.unwrap_or(base.known_network_max_per_account),
			..base
		}
	}
}

#[cfg(test)]
mod tests;
