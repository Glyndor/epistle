//! Sender Rewriting Scheme secrets: the server-wide `srs_secret` and the
//! `[[srs_domain]]` entries that give a hosted domain its own.
//!
//! One secret for every domain means one domain's address, once leaked or
//! replayed, is a valid address for all of them, and rotating it breaks every
//! domain at once. A domain with its own secret signs and verifies with that
//! secret alone. An installation that never added an entry keeps working
//! with `srs_secret` exactly as before.

use serde::Deserialize;

mod notices;
mod validate;

/// One hosted domain's SRS secret.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SrsDomain {
	/// The hosted domain whose forwarded mail the secret signs, matched
	/// without regard to case.
	pub name: String,
	/// The secret that signs and verifies this domain's SRS addresses.
	pub secret: String,
	/// The secret `secret` replaced. It only verifies: an address made
	/// before a rotation is still returned for its remaining lifetime. Remove
	/// it once that lifetime (14 days) has passed.
	#[serde(default)]
	pub previous_secret: Option<String>,
}

impl std::fmt::Debug for SrsDomain {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SrsDomain")
			.field("name", &self.name)
			.field("secret", &"***")
			.field(
				"previous_secret",
				&self.previous_secret.as_ref().map(|_| "***"),
			)
			.finish()
	}
}

impl super::Config {
	/// The `[[srs_domain]]` entry for `domain`, compared without regard to case.
	pub fn srs_domain(&self, domain: &str) -> Option<&SrsDomain> {
		self.srs_domain
			.iter()
			.find(|entry| entry.name.eq_ignore_ascii_case(domain))
	}

	/// Whether the server rewrites forwarded mail's sender at all: a
	/// server-wide secret or at least one domain secret is set.
	pub fn srs_enabled(&self) -> bool {
		self.srs_secret.is_some() || !self.srs_domain.is_empty()
	}

	/// The keys SRS signs and verifies with, built from the configuration.
	pub fn srs_keys(&self) -> crate::queue::srs::SrsKeys {
		use crate::queue::srs::{Srs, SrsKeys};
		let mut keys = SrsKeys::default();
		if let Some(secret) = &self.srs_secret {
			keys = keys.with_global(Srs::new(secret.as_bytes()));
		}
		for entry in &self.srs_domain {
			let previous = entry
				.previous_secret
				.as_ref()
				.map(|secret| Srs::new(secret.as_bytes()));
			keys = keys.with_domain(&entry.name, Srs::new(entry.secret.as_bytes()), previous);
		}
		keys
	}
}

#[cfg(test)]
mod tests;
