//! Validation of `send_only_domains`.

use std::collections::HashSet;

use super::{Config, ConfigError};

impl Config {
	/// Every `send_only_domains` entry names a configured domain, once.
	pub(super) fn validate_send_only_domains(&self) -> Result<(), ConfigError> {
		let hosted: HashSet<String> = self
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let mut seen = HashSet::new();
		for domain in &self.send_only_domains {
			let lower = domain.to_ascii_lowercase();
			if !hosted.contains(&lower) {
				return Err(ConfigError::Invalid(format!(
					"send_only_domains entry \"{domain}\" is not in domains"
				)));
			}
			if !seen.insert(lower) {
				return Err(ConfigError::Invalid(format!(
					"duplicate send_only_domains entry \"{domain}\""
				)));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
