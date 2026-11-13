//! Validation of `[dns_publish] senders`, split out of
//! `src/config/validate/mod.rs` to keep both files under the per-file line
//! limit.

use std::collections::HashSet;

use super::{Config, ConfigError, validate_dns_name};

impl Config {
	/// Every `senders` entry is a valid ASCII DNS name, once, at or under a
	/// hosted domain: a name outside them is never locked down, so listing
	/// it can only be a typo.
	pub(super) fn validate_dns_senders(&self) -> Result<(), ConfigError> {
		let mut seen = HashSet::new();
		for name in &self.dns_publish.senders {
			validate_dns_name("[dns_publish] senders entry", name)?;
			let lower = name.trim().to_ascii_lowercase();
			let hosted = self.domains.iter().any(|domain| {
				let domain = domain.to_ascii_lowercase();
				lower == domain || lower.ends_with(&format!(".{domain}"))
			});
			if !hosted {
				return Err(ConfigError::Invalid(format!(
					"[dns_publish] senders entry \"{name}\" is not a hosted domain or a name under one"
				)));
			}
			if !seen.insert(lower) {
				return Err(ConfigError::Invalid(format!(
					"duplicate [dns_publish] senders entry \"{name}\""
				)));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
