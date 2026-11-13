//! The role of each hosted domain, and the one set of skipped groups the
//! DNS commands read.

use crate::dns::skip::{DomainRole, Roles, SkipSet};

use super::Config;

impl Config {
	/// The role of `domain`: `disabled` when `disabled_domains` lists it
	/// (whatever else does), then `send-only` or `receive-only` when the
	/// list of that role has it, `full` otherwise.
	pub fn domain_role(&self, domain: &str) -> DomainRole {
		self.roles().of_name(domain)
	}

	/// The roles of every hosted domain.
	pub fn roles(&self) -> Roles {
		Roles::new(&self.domains, &self.send_only_domains)
			.with_others(&self.receive_only_domains, &self.disabled_domains)
	}

	/// The groups of records the configuration leaves out: the
	/// `[dns_publish] skip` groups everywhere, and what the role of each
	/// domain omits for that domain. `dns-records`, `domain add`,
	/// `verify-dns`, `status` and the publisher all filter with this set, so
	/// what is printed is what is checked and what is written.
	pub fn skip_set(&self) -> SkipSet {
		self.dns_publish.skip_set().with_roles(self.roles())
	}
}
