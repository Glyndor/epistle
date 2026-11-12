//! Validation of `receive_only_domains`.

use std::collections::HashSet;

use super::{Config, ConfigError};

impl Config {
	/// Every `receive_only_domains` entry names a configured domain, once,
	/// and none is also `send_only_domains`: a domain that neither sends nor
	/// receives is switched off with `disabled_domains`, so listing it in
	/// both is a mistake to refuse and not a role to guess.
	pub(super) fn validate_receive_only_domains(&self) -> Result<(), ConfigError> {
		let hosted: HashSet<String> = self
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let send_only: HashSet<String> = self
			.send_only_domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let mut seen = HashSet::new();
		for domain in &self.receive_only_domains {
			let lower = domain.to_ascii_lowercase();
			if !hosted.contains(&lower) {
				return Err(ConfigError::Invalid(format!(
					"receive_only_domains entry \"{domain}\" is not in domains"
				)));
			}
			if send_only.contains(&lower) {
				return Err(ConfigError::Invalid(format!(
					"\"{domain}\" is in both send_only_domains and receive_only_domains; \
					 a domain that neither sends nor receives goes in disabled_domains"
				)));
			}
			if !seen.insert(lower) {
				return Err(ConfigError::Invalid(format!(
					"duplicate receive_only_domains entry \"{domain}\""
				)));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
