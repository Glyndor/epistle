//! `[dkim]` validation: the RSA pair of the default and of every
//! `[[dkim.domain]]` entry is complete, and every entry names a hosted
//! domain, once. Kept beside the type rather than in `validate.rs`, which
//! is at the line limit.

use std::collections::{HashMap, HashSet};

use crate::config::{ConfigError, Dkim};

impl Dkim {
	/// Check the block against the hosted `domains` and `domain_aliases`.
	pub(in crate::config) fn validate(
		&self,
		domains: &[String],
		domain_aliases: &HashMap<String, String>,
	) -> Result<(), ConfigError> {
		// The RSA selector and key file are a pair: the configured selector
		// points at a `_domainkey` TXT published for the key, so leaving one
		// side unset means the published record is unreachable (or, if the
		// key file is set without the selector, the key has no TXT at all).
		// Treat the half-configured state as a load-time error so it cannot
		// ship.
		match (&self.rsa_selector, &self.rsa_key_file) {
			(Some(_), Some(_)) | (None, None) => {}
			_ => {
				return Err(ConfigError::Invalid(
					"rsa_selector and rsa_key_file must be set together".into(),
				));
			}
		}
		validate_dkim_overrides(self, domains, domain_aliases)
	}
}

/// The set the server signs for, projected from the configured domains
/// and aliases. Case-insensitive so `Example.org` and `example.org`
/// resolve to the same key, the same way the routing layer compares
/// them at delivery time.
fn hosted_set(domains: &[String], domain_aliases: &HashMap<String, String>) -> HashSet<String> {
	let mut all = HashSet::new();
	for domain in domains {
		all.insert(domain.to_ascii_lowercase());
	}
	for alias in domain_aliases.keys() {
		all.insert(alias.to_ascii_lowercase());
	}
	all
}

/// Apply the per-domain DKIM rules: every override must name a hosted
/// domain, its RSA fields must be a complete pair, and the same domain
/// must not be listed twice. The half-configured RSA pair matches the
/// rule the configured `[dkim]` block applies, so the operator reads
/// the same shape of error from both.
fn validate_dkim_overrides(
	dkim: &Dkim,
	domains: &[String],
	domain_aliases: &HashMap<String, String>,
) -> Result<(), ConfigError> {
	if dkim.domain.is_empty() {
		return Ok(());
	}
	let hosted = hosted_set(domains, domain_aliases);
	let mut seen = HashSet::new();
	for entry in &dkim.domain {
		if !entry.rsa_pair_is_complete() {
			return Err(ConfigError::Invalid(format!(
				"[dkim.domain] name = \"{}\": rsa_selector and rsa_key_file must be set together",
				entry.name
			)));
		}
		let name = entry.name.to_ascii_lowercase();
		if !hosted.contains(&name) {
			return Err(ConfigError::Invalid(format!(
				"[dkim.domain] name = \"{}\" is not in [domains] or [domain_aliases]; \
				 per-domain keys can only sign domains the server hosts",
				entry.name
			)));
		}
		if !seen.insert(name.clone()) {
			return Err(ConfigError::Invalid(format!(
				"[dkim.domain] name = \"{name}\" is listed more than once"
			)));
		}
	}
	Ok(())
}

#[cfg(test)]
#[path = "validate_dkim_domain_tests.rs"]
mod tests;
