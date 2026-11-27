//! The cap each tenant puts on the accounts it holds.
//!
//! The rule lives here so the two places that enforce it agree: the API's
//! early check, which refuses before a password is derived, and the store's
//! locked write, which counts the accounts the file holds now and inserts in
//! the same step. Both report the same refusal, so a request refused by one
//! and a request refused by the other answer alike.

use std::collections::HashSet;

use crate::config::Tenant;

/// One tenant's cap on accounts: the domains it owns, the name it is
/// reported under, and the number of accounts it may hold.
#[derive(Clone, Debug)]
struct TenantAccountCap {
	/// The configured `name`, or `<unnamed tenant>`.
	label: String,
	/// The domains of the tenant, lowercased.
	domains: HashSet<String>,
	/// The most accounts the tenant may hold.
	max_accounts: u64,
}

/// The caps of every tenant, in configuration order.
#[derive(Clone, Debug, Default)]
pub struct TenantAccountCaps {
	caps: Vec<TenantAccountCap>,
}

impl TenantAccountCaps {
	/// The caps the tenants declare. A tenant without `max_accounts` caps
	/// nothing and is left out; the order of the file is kept, so the first
	/// tenant at its cap is the one reported.
	pub fn from_tenants(tenants: &[Tenant]) -> Self {
		let caps = tenants
			.iter()
			.filter_map(|tenant| {
				let max_accounts = tenant.max_accounts?;
				Some(TenantAccountCap {
					label: tenant
						.name
						.clone()
						.unwrap_or_else(|| "<unnamed tenant>".to_string()),
					domains: tenant
						.domains
						.iter()
						.map(|domain| domain.to_ascii_lowercase())
						.collect(),
					max_accounts,
				})
			})
			.collect();
		TenantAccountCaps { caps }
	}

	/// Whether no tenant caps its accounts.
	pub fn is_empty(&self) -> bool {
		self.caps.is_empty()
	}

	/// The refusal when `addresses` would take a place in a tenant that
	/// already holds as many accounts as its cap allows. `accounts` are the
	/// addresses of every account the store holds now; the candidate is not
	/// among them yet.
	pub fn refuse_creation<'a>(
		&self,
		addresses: &[String],
		accounts: impl IntoIterator<Item = &'a [String]>,
	) -> Option<String> {
		self.refuse(addresses, &[], accounts)
	}

	/// The refusal when `proposed` would move an account into a tenant it
	/// does not count against yet. A tenant the account already holds keeps
	/// the one place it has, so only the tenants it enters are checked.
	pub fn refuse_move<'a>(
		&self,
		current: &[String],
		proposed: &[String],
		accounts: impl IntoIterator<Item = &'a [String]>,
	) -> Option<String> {
		self.refuse(proposed, current, accounts)
	}

	/// The refusal for `addresses`, skipping the tenants `held` already
	/// counts against.
	fn refuse<'a>(
		&self,
		addresses: &[String],
		held: &[String],
		accounts: impl IntoIterator<Item = &'a [String]>,
	) -> Option<String> {
		let accounts: Vec<&[String]> = accounts.into_iter().collect();
		for cap in &self.caps {
			if !touches(cap, addresses) || touches(cap, held) {
				continue;
			}
			let count = accounts
				.iter()
				.filter(|addresses| touches(cap, addresses))
				.count() as u64;
			if count + 1 > cap.max_accounts {
				return Some(refusal(&cap.label, cap.max_accounts));
			}
		}
		None
	}
}

/// Whether `addresses` touch the tenant.
fn touches(cap: &TenantAccountCap, addresses: &[String]) -> bool {
	addresses.iter().any(|raw| {
		raw.rsplit_once('@')
			.is_some_and(|(_, domain)| cap.domains.contains(&domain.to_ascii_lowercase()))
	})
}

/// The refusal the API, the CLI and the store report alike.
fn refusal(label: &str, cap: u64) -> String {
	format!("tenant \"{label}\" has reached its max_accounts cap of {cap}")
}
