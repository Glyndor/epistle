//! Addresses claimed by more than one owner once they are compared in their
//! stored form.
//!
//! Every write path refuses an address another owner already has, so a
//! collision only exists in data written before addresses were lowercased
//! (two accounts with `Ärger@` and `ärger@`, which used to be different
//! mailboxes), or in files edited by hand. Nothing is merged and nothing is
//! deleted: the first owner (static accounts in `mail.toml` order, then
//! `accounts.toml` in file order) keeps the address for delivery and login,
//! the later claim stays on disk unused, and [`AccountStore::address_collisions`]
//! names both so the server log and `epistle status` can tell the operator.

use super::AccountStore;
use crate::util::address::normalize;

impl AccountStore {
	/// One line per address claimed by two owners, naming both and the one
	/// that keeps it.
	pub fn address_collisions(&self) -> Vec<String> {
		let dynamic = self.dynamic.read().expect("store lock");
		let masked = self.masked.read().expect("masked lock");
		let static_claims = self.static_accounts.iter().flat_map(|account| {
			let owner = format!("account \"{}\" (mail.toml)", account.name);
			account
				.addresses
				.iter()
				.map(move |a| (a.clone(), owner.clone()))
		});
		let dynamic_claims = dynamic.iter().flat_map(|account| {
			let owner = format!("account \"{}\" (accounts.toml)", account.name);
			account
				.addresses
				.iter()
				.map(move |a| (a.clone(), owner.clone()))
		});
		let alias_claims = self.aliases.iter().map(|alias| {
			(
				alias.address.clone(),
				format!("alias {} (mail.toml)", alias.address),
			)
		});
		let masked_claims = masked
			.all()
			.map(|(address, account)| (address, format!("a masked address of \"{account}\"")));
		let mut first: std::collections::HashMap<String, String> = Default::default();
		let mut collisions = Vec::new();
		for (address, owner) in static_claims
			.chain(dynamic_claims)
			.chain(alias_claims)
			.chain(masked_claims)
		{
			let key = normalize(&address);
			match first.get(&key) {
				Some(keeper) if *keeper != owner => collisions.push(format!(
					"address {key} is claimed by {keeper} and by {owner}; {keeper} keeps it"
				)),
				Some(_) => {}
				None => {
					first.insert(key, owner);
				}
			}
		}
		collisions
	}
}

#[cfg(test)]
#[path = "collisions_tests.rs"]
mod tests;
