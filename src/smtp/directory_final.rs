//! Where a recipient address is finally delivered, with the address each
//! copy is delivered as. Kept apart from `directory.rs`, which holds the
//! lookup tables and the resolution rules this builds on.

use super::{Directory, Resolution};
use crate::smtp::address::Address;
use crate::util::address::normalize;

impl Directory {
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
