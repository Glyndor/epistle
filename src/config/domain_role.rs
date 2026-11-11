//! The role of each hosted domain, and the one set of skipped groups the
//! DNS commands read.

use crate::dns::skip::{DomainRole, Roles, SkipSet};

use super::Config;

impl Config {
	/// The role of `domain`: `send-only` when `send_only_domains` lists it,
	/// `full` otherwise.
	pub fn domain_role(&self, domain: &str) -> DomainRole {
		if self
			.send_only_domains
			.iter()
			.any(|listed| listed.eq_ignore_ascii_case(domain))
		{
			DomainRole::SendOnly
		} else {
			DomainRole::Full
		}
	}

	/// The groups of records the configuration leaves out: the
	/// `[dns_publish] skip` groups everywhere, and what the role of each
	/// domain omits for that domain. `dns-records`, `domain add`,
	/// `verify-dns`, `status` and the publisher all filter with this set, so
	/// what is printed is what is checked and what is written.
	pub fn skip_set(&self) -> SkipSet {
		self.dns_publish
			.skip_set()
			.with_roles(Roles::new(&self.domains, &self.send_only_domains))
	}
}
