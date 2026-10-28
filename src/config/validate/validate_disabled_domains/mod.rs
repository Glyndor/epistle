//! Validation of `disabled_domains`, split out of `validate.rs` to keep both
//! files under the per-file line limit.

use std::collections::HashSet;

use super::{Config, ConfigError};

impl Config {
	/// Every `disabled_domains` entry names a configured domain, once. The
	/// alias domains follow their target and cannot be switched off alone.
	/// With listeners configured at least one domain must stay enabled, so a
	/// server is never left accepting connections for nothing.
	pub(super) fn validate_disabled_domains(&self) -> Result<(), ConfigError> {
		let hosted: HashSet<String> = self
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let mut seen = HashSet::new();
		for domain in &self.disabled_domains {
			let lower = domain.to_ascii_lowercase();
			if !hosted.contains(&lower) {
				return Err(ConfigError::Invalid(format!(
					"disabled_domains entry \"{domain}\" is not in domains"
				)));
			}
			if !seen.insert(lower) {
				return Err(ConfigError::Invalid(format!(
					"duplicate disabled_domains entry \"{domain}\""
				)));
			}
		}
		if !self.listeners.is_empty() && !hosted.is_empty() && seen.len() == hosted.len() {
			return Err(ConfigError::Invalid(
				"disabled_domains switches off every entry of domains; \
				 remove the listeners or keep one domain enabled"
					.into(),
			));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
