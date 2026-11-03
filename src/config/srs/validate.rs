//! SRS validation: every `[[srs_domain]]` names a hosted domain once, no
//! secret is used by two domains (or by a domain and the server-wide
//! `srs_secret`), and forwarding has a secret to sign with.

use std::collections::{HashMap, HashSet};

use crate::config::{Config, ConfigError};

/// Shortest secret an `[[srs_domain]]` entry may carry. `epistle` writes 43
/// characters; this only turns away a placeholder.
const MIN_SECRET_LEN: usize = 16;

impl Config {
	/// Check the SRS secrets against the hosted domains and the accounts that
	/// forward.
	pub(in crate::config) fn validate_srs(&self) -> Result<(), ConfigError> {
		self.validate_srs_domains()?;
		self.validate_srs_coverage()
	}

	/// The entries name hosted domains once and keep their secrets apart.
	fn validate_srs_domains(&self) -> Result<(), ConfigError> {
		let hosted: HashSet<String> = self
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let mut names = HashSet::new();
		// Who holds each secret already, so the message names both.
		let mut holders: HashMap<&str, String> = HashMap::new();
		if let Some(global) = &self.srs_secret {
			holders.insert(global, "the server-wide `srs_secret`".to_string());
		}
		for entry in &self.srs_domain {
			let name = entry.name.to_ascii_lowercase();
			crate::config::validate_dns_name("srs_domain name", &entry.name)?;
			if !hosted.contains(&name) {
				return Err(ConfigError::Invalid(format!(
					"[[srs_domain]] name = \"{}\" is not in `domains`; a secret can only \
					 sign a domain the server hosts",
					entry.name
				)));
			}
			if !names.insert(name.clone()) {
				return Err(ConfigError::Invalid(format!(
					"[[srs_domain]] name = \"{name}\" is listed more than once"
				)));
			}
			let held =
				std::iter::once(entry.secret.as_str()).chain(entry.previous_secret.as_deref());
			for secret in held {
				if secret.len() < MIN_SECRET_LEN {
					return Err(ConfigError::Invalid(format!(
						"[[srs_domain]] \"{name}\" has a secret shorter than {MIN_SECRET_LEN} characters; \
						 `epistle srs split` writes a strong one"
					)));
				}
				let owner = format!("the domain \"{name}\"");
				match holders.get(secret) {
					Some(other) if *other == owner => {
						return Err(ConfigError::Invalid(format!(
							"[[srs_domain]] \"{name}\" uses the same value for `secret` and `previous_secret`; \
							 a rotation replaces the secret"
						)));
					}
					Some(other) => {
						return Err(ConfigError::Invalid(format!(
							"[[srs_domain]] \"{name}\" shares a secret with {other}; \
							 a domain's SRS addresses must be signed by that domain alone \
							 (`epistle srs split` writes a secret of its own for each domain)"
						)));
					}
					None => {
						holders.insert(secret, owner);
					}
				}
			}
		}
		Ok(())
	}

	/// An account that forwards needs a secret for its domains: its own
	/// `[[srs_domain]]`, or the server-wide `srs_secret`.
	///
	/// The recommended SPF policy for our domains is `-all` (hardfail), see
	/// `dns::records::build_records`, and `-all` only stays safe to publish
	/// because forwarding rewrites the envelope sender onto our own domain
	/// (SRS), so the next hop evaluates SPF against our record and passes.
	/// Without SRS, forwarded mail keeps the original sender; the recipient
	/// MTA's SPF check on the original domain fails, and any domain that
	/// publishes `-all` rejects the message. Refusing here surfaces the
	/// mismatch at load time rather than at the first forwarded bounce.
	fn validate_srs_coverage(&self) -> Result<(), ConfigError> {
		if self.srs_secret.is_some() {
			return Ok(());
		}
		let uncovered: Vec<String> = self
			.accounts
			.iter()
			.filter(|account| !account.forward.is_empty())
			.filter(|account| {
				account.addresses.is_empty()
					|| account.addresses.iter().any(|address| {
						address
							.rsplit_once('@')
							.is_none_or(|(_, domain)| self.srs_domain(domain).is_none())
					})
			})
			.map(|account| format!("\"{}\"", account.name))
			.collect();
		if uncovered.is_empty() {
			return Ok(());
		}
		Err(ConfigError::Invalid(format!(
			"[[accounts]] {} set `forward = [...]` but no `srs_secret` is configured and \
			 their domain has no [[srs_domain]]; without SRS, forwarded mail keeps the \
			 original envelope sender and any destination whose SPF policy is `-all` will \
			 reject the message. Set `srs_secret`, add an [[srs_domain]] for the domain \
			 (`epistle srs split`), or remove the `forward` entries.",
			uncovered.join(", ")
		)))
	}
}
