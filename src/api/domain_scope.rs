//! Which domains an API key may act on.
//!
//! epistle's API authenticates a *key*, not an account, so multi-tenancy here
//! is a property of the key rather than of a logged-in administrator. A key
//! that declares no domains keeps the reach it has always had; one that
//! declares them is confined to those domains and to the accounts that live
//! entirely inside them.

use super::api_keys::ApiKey;

/// The domains a request is allowed to touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainScope {
	/// Every configured domain. The static token, and any key that declares
	/// no domains, so an install that never heard of tenancy is unaffected.
	All,
	/// Only these domains, lowercased.
	Only(Vec<String>),
}

impl DomainScope {
	/// The scope a key carries. An empty `domains` list means [`Self::All`].
	pub fn of_key(key: &ApiKey) -> Self {
		if key.domains.is_empty() {
			return Self::All;
		}
		Self::Only(
			key.domains
				.iter()
				.map(|domain| domain.to_ascii_lowercase())
				.collect(),
		)
	}

	/// Whether `domain` is inside the scope. Comparison is case-insensitive,
	/// because DNS is.
	pub fn admits_domain(&self, domain: &str) -> bool {
		match self {
			Self::All => true,
			Self::Only(domains) => {
				let domain = domain.to_ascii_lowercase();
				domains.contains(&domain)
			}
		}
	}

	/// Whether an account whose addresses are `addresses` is inside the scope.
	///
	/// `all`, not `any`. An account holding one address inside the scope and
	/// another outside it belongs to both tenants at once: deleting it, or
	/// changing its password, reaches a domain this key was not given. One
	/// matching address must not vouch for the rest, so a straddling account
	/// is out of scope for everyone but an unrestricted key.
	///
	/// An account with no addresses at all is out of scope for a restricted
	/// key: there is nothing to place it in a tenant, and failing closed is
	/// the only safe reading of "no evidence".
	pub fn admits_account<'a>(&self, mut addresses: impl Iterator<Item = &'a str>) -> bool {
		match self {
			Self::All => true,
			Self::Only(_) => {
				let mut seen = false;
				let admits_every = addresses.all(|address| {
					seen = true;
					address
						.rsplit_once('@')
						.is_some_and(|(_, domain)| self.admits_domain(domain))
				});
				seen && admits_every
			}
		}
	}
}

#[cfg(test)]
#[path = "domain_scope_tests.rs"]
mod tests;
