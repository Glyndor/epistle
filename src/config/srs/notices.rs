//! What `status` and `config-check` say about SRS secrets that are shared.

use crate::config::Config;

impl Config {
	/// The hosted, enabled domains that sign with the server-wide
	/// `srs_secret` because they have no `[[srs_domain]]` of their own. Empty
	/// when the server-wide secret is not set.
	pub fn srs_domains_on_shared_secret(&self) -> Vec<String> {
		if self.srs_secret.is_none() {
			return Vec::new();
		}
		self.enabled_domains()
			.into_iter()
			.filter(|domain| self.srs_domain(domain).is_none())
			.collect()
	}

	/// The advisories about SRS secrets: one when two or more hosted domains
	/// still share `srs_secret`. A single domain on it shares with nobody.
	pub fn srs_notices(&self) -> Vec<String> {
		let shared = self.srs_domains_on_shared_secret();
		if shared.len() < 2 {
			return Vec::new();
		}
		vec![format!(
			"{} domains sign their forwarded mail with the same `srs_secret` ({}); an \
			 address made for one verifies for the others and one rotation breaks all of \
			 them. `epistle srs split` gives each its own secret and keeps `srs_secret` \
			 verifying the addresses already out",
			shared.len(),
			shared.join(", ")
		)]
	}
}
