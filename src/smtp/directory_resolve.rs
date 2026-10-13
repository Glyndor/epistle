//! Recipient resolution: what an address names (an account, an alias, a
//! masked address, a sub-address, a catch-all), and where it is finally
//! delivered, with the address each copy is delivered as. Kept apart from
//! `directory.rs`, which holds the lookup tables.

use super::{Directory, Resolution};
use crate::smtp::address::Address;
use crate::util::address::normalize;

impl Directory {
	/// Resolve a validated address.
	pub fn resolve(&self, address: &Address) -> Resolution {
		let local = address.local_part();
		// A domain alias resolves as its target domain.
		let domain = self
			.domain_aliases
			.get(address.domain())
			.map(String::as_str)
			.unwrap_or(address.domain());
		if !self.domains.contains(domain) {
			return Resolution::NotLocal;
		}
		let key = normalize(&format!("{local}@{domain}"));
		if let Some(account) = self.accounts_by_address.get(&key) {
			return Resolution::Account(account.clone());
		}
		// Multi-target alias: fan out to its member accounts.
		if let Some(spec) = self.aliases.get(&key) {
			let accounts = spec
				.members
				.iter()
				.filter_map(|member| self.accounts_by_address.get(&normalize(member)))
				.cloned()
				.collect();
			return Resolution::Alias(accounts);
		}
		// Enabled masked email address: deliver to its owner. Disabled masks
		// are absent here, so they reject identically to unknown users.
		if let Some(account) = self.masked_by_address.get(&key) {
			return Resolution::Account(account.clone());
		}
		// Sub-addressing: strip the tag and retry the base address.
		if let Some(base) = self.strip_subaddress(local, domain)
			&& let Some(account) = self.accounts_by_address.get(&base)
		{
			return Resolution::Account(account.clone());
		}
		// Catch-all: a domain may funnel its unknown local users to one account.
		if let Some(account) = self.catch_all.get(domain) {
			return Resolution::Account(account.clone());
		}
		Resolution::UnknownUser
	}

	/// The base `local@domain` key (lowercased) once the earliest sub-address
	/// separator and everything after it are removed, or `None` if the
	/// local part carries no tag.
	fn strip_subaddress(&self, local: &str, domain: &str) -> Option<String> {
		let cut = self
			.subaddress_separators
			.iter()
			.filter_map(|sep| local.find(*sep))
			.min()?;
		// A leading separator (e.g. `+tag`) leaves no base local-part.
		if cut == 0 {
			return None;
		}
		Some(normalize(&format!("{}@{}", &local[..cut], domain)))
	}

	/// The accounts `address` delivers to, each with the address its copy
	/// is delivered as: a member's own address for a multi-target alias,
	/// `address` itself (lowercased) for everything else that resolves to
	/// an account. `None` when the address is not local or names no one; an
	/// alias whose members all left yields an empty list.
	pub fn final_recipients(&self, address: &Address) -> Option<Vec<(String, String)>> {
		match self.resolve(address) {
			Resolution::Account(account) => Some(vec![(account, normalize(&address.to_string()))]),
			Resolution::Alias(_) => {
				let domain = self
					.domain_aliases
					.get(address.domain())
					.map(String::as_str)
					.unwrap_or(address.domain());
				let key = normalize(&format!("{}@{domain}", address.local_part()));
				let spec = self.aliases.get(&key)?;
				Some(
					spec.members
						.iter()
						.filter_map(|member| {
							let member = normalize(member);
							let account = self.accounts_by_address.get(&member)?;
							Some((account.clone(), member))
						})
						.collect(),
				)
			}
			Resolution::NotLocal | Resolution::UnknownUser => None,
		}
	}
}
