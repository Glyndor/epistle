//! `[dns_publish]`: how automatic mode keeps the DNS records true.
//!
//! With a `[dns]` provider that can write, the server compares the zones with
//! the configuration every `interval_secs` and applies the difference through
//! the code `epistle dns publish` runs. Without one (manual mode) none of
//! this runs and the section is only read by the command.
//!
//! The `skip` list names the groups of records automatic mode must not
//! publish: the records of a group are never written, and a record epistle
//! published earlier is retired through the ledger like a record the
//! configuration no longer needs.

use serde::Deserialize;

use super::ConfigError;
use crate::dns::skip::{SkipGroup, SkipSet};

/// Six hours between two runs of the reconcile loop.
pub const DEFAULT_INTERVAL_SECS: u64 = 21_600;

/// The shortest interval accepted: ten minutes. Shorter would spend the
/// provider's API quota on a zone that rarely changes.
pub const MIN_INTERVAL_SECS: u64 = 600;

/// The longest interval accepted: one week.
pub const MAX_INTERVAL_SECS: u64 = 604_800;

/// The `[dns_publish]` section.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsPublish {
	/// Seconds between two runs of the server's reconcile loop in automatic
	/// mode; `0` turns the loop off. Between 600 and 604800 otherwise.
	#[serde(default = "default_interval")]
	pub interval_secs: u64,
	/// The named groups automatic mode must not publish. Empty by default:
	/// every record the configuration needs is published.
	#[serde(default)]
	pub skip: Vec<SkipGroup>,
}

impl Default for DnsPublish {
	fn default() -> Self {
		DnsPublish {
			interval_secs: DEFAULT_INTERVAL_SECS,
			skip: Vec::new(),
		}
	}
}

fn default_interval() -> u64 {
	DEFAULT_INTERVAL_SECS
}

impl DnsPublish {
	/// The groups to skip, as a set the record filter reads.
	pub fn skip_set(&self) -> SkipSet {
		SkipSet::new(self.skip.iter().copied())
	}

	/// Refuse an interval outside the accepted range.
	pub(crate) fn validate(&self) -> Result<(), ConfigError> {
		let secs = self.interval_secs;
		if secs != 0 && !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&secs) {
			return Err(ConfigError::Invalid(format!(
				"[dns_publish] interval_secs = {secs}: use 0 to turn the reconcile loop off, or a value from {MIN_INTERVAL_SECS} to {MAX_INTERVAL_SECS}"
			)));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
