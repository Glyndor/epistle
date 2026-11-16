//! The `[forwarding]` section: who may have mail forwarded off this server,
//! and how much of it an account may send on that way.
//!
//! Forwarding is any copy an account's mail makes on its own: the
//! account's `forward` addresses, a Sieve `redirect` and a vacation reply.
//! `policy` says where such a copy may go; the limits count them like
//! submissions, so an account cannot send through a script what it could
//! not send itself. A `[[antispam_scope]]` may set `forward_policy` and
//! `forward_per_min` for a tenant, a domain or an account; the most
//! specific scope in reach wins.

use serde::Deserialize;

use super::{Config, ConfigError};

/// Where a forwarded copy may go.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub enum ForwardPolicy {
	/// Any address. What the server did before this setting existed.
	#[default]
	#[serde(rename = "any")]
	Any,
	/// Only an address in a domain this server hosts.
	#[serde(rename = "hosted-only")]
	HostedOnly,
	/// Nowhere: no `forward` address, no `redirect` and no vacation reply
	/// leaves the account.
	#[serde(rename = "none")]
	None,
}

impl ForwardPolicy {
	/// Whether a copy to `address` is allowed when `hosted` says whether
	/// the address's domain is one this server hosts.
	pub fn allows(self, hosted: bool) -> bool {
		match self {
			Self::Any => true,
			Self::HostedOnly => hosted,
			Self::None => false,
		}
	}
}

/// The `[forwarding]` section.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Forwarding {
	/// Where forwarded copies may go (default `any`).
	pub policy: ForwardPolicy,
	/// The most copies one account may forward in a minute. Absent follows
	/// the account's submission limit (its domain's, else
	/// `submission_rate_limit_per_min`), and no limit when that is absent
	/// too.
	pub account_per_min: Option<u32>,
	/// The most copies the whole server forwards in a minute, across every
	/// account. Absent sets none.
	pub server_per_min: Option<u32>,
}

impl Config {
	/// Check `[forwarding]` and the forwarding keys of every scope: a limit
	/// is at least one copy, because `0` would read as "no limit".
	pub(super) fn validate_forwarding(&self) -> Result<(), ConfigError> {
		for (key, value) in [
			("account_per_min", self.forwarding.account_per_min),
			("server_per_min", self.forwarding.server_per_min),
		] {
			if value == Some(0) {
				return Err(ConfigError::Invalid(format!(
					"[forwarding] {key} must be at least 1; remove the key for no limit"
				)));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
