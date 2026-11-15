//! The role of each hosted domain, and the one set of skipped groups the
//! DNS commands read.

use crate::dns::skip::{DomainRole, Roles, SkipGroup, SkipSet};

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
	/// `[dns_publish] skip` groups everywhere, what the role of each
	/// domain omits for that domain, and the DANE record while the
	/// operator has not said the zone is signed. `dns-records`,
	/// `domain add`, `verify-dns`, `status` and the publisher all
	/// filter with this set, so what is printed is what is checked and
	/// what is written.
	pub fn skip_set(&self) -> SkipSet {
		let set = self.dns_publish.skip_set().with_roles(self.roles());
		if self.dns_publish.dane {
			set
		} else {
			// The DANE record is only safe in a zone that is signed with
			// DNSSEC, and the operator says so with `[dns_publish]
			// dane`. While they have not, the record is skipped like a
			// group the operator skipped: the filter drops it and the
			// certificate refresh does not publish it.
			set.with_group(SkipGroup::Tlsa)
		}
	}
}
