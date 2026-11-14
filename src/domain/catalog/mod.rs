//! What each hosted domain is: whether it takes mail, its role, its alias
//! edges, its overrides and what in the configuration file relies on it.
//!
//! `epistle domain list` and `epistle domain show` print it, and the
//! `/api/v1/domains` routes answer with it, so the command and the routes
//! read the configuration through this one function and cannot drift apart:
//! the JSON a route returns for a domain is the object `epistle domain show
//! --json` prints for it. A route only adds what it owes the caller on top,
//! the filter to the domains a key is confined to.
//!
//! The server builds its catalog once, from the configuration it started
//! with. A change written to the file later shows in the routes after the
//! restart that applies it, the same moment the server starts acting on it.

use serde::Serialize;

use crate::config::Config;
use crate::dns::skip::Roles;

/// One hosted domain as `epistle domain list --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainRow {
	/// The domain as the configuration spells it.
	pub domain: String,
	/// `false` when the domain is in `disabled_domains`: mail for it is
	/// rejected and nobody may send as it.
	pub enabled: bool,
	/// `full`, `send-only`, `receive-only` or `disabled`.
	pub role: &'static str,
	/// The alias domains that resolve as this one.
	pub aliases_to: Vec<String>,
	/// The domains this one resolves as, when it is itself an alias.
	pub aliases_from: Vec<String>,
}

/// One hosted domain as `epistle domain show --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainView {
	/// The domain as the caller named it.
	pub domain: String,
	/// See [`DomainRow::enabled`].
	pub enabled: bool,
	/// See [`DomainRow::role`].
	pub role: &'static str,
	/// The default storage quota of the domain's accounts in bytes, when the
	/// domain overrides the server's.
	pub quota: Option<u64>,
	/// Messages per minute an authenticated sender in the domain may
	/// submit, when the domain overrides the server's.
	pub submission_rate: Option<u32>,
	/// See [`DomainRow::aliases_to`].
	pub aliases_to: Vec<String>,
	/// See [`DomainRow::aliases_from`].
	pub aliases_from: Vec<String>,
	/// The addresses in the domain held by accounts declared in the
	/// configuration file. Accounts made through the API or `epistle account
	/// add` are not listed.
	pub accounts: Vec<String>,
	/// The `[[alias]]` addresses in the domain.
	pub aliases: Vec<String>,
}

impl DomainView {
	/// The row of the same domain.
	pub fn row(&self) -> DomainRow {
		DomainRow {
			domain: self.domain.clone(),
			enabled: self.enabled,
			role: self.role,
			aliases_to: self.aliases_to.clone(),
			aliases_from: self.aliases_from.clone(),
		}
	}
}

/// Every hosted domain, in the order of `domains`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
	views: Vec<DomainView>,
}

impl Catalog {
	/// The catalog of `config`.
	pub fn from_config(config: &Config) -> Self {
		let roles = config.roles();
		let views = config
			.domains
			.iter()
			.map(|domain| view_of(config, &roles, domain))
			.collect();
		Catalog { views }
	}

	/// The catalog of a server that knows only its domains and which of them
	/// are switched off: no aliases, overrides or declared accounts. What an
	/// API state built without a configuration file holds.
	pub fn hosting(domains: &[String], disabled: &[String]) -> Self {
		let roles = Roles::new(domains, &[]).with_others(&[], disabled);
		let views = domains
			.iter()
			.map(|domain| DomainView {
				domain: domain.clone(),
				enabled: !listed(disabled, domain),
				role: roles.of_name(domain).name(),
				quota: None,
				submission_rate: None,
				aliases_to: Vec::new(),
				aliases_from: Vec::new(),
				accounts: Vec::new(),
				aliases: Vec::new(),
			})
			.collect();
		Catalog { views }
	}

	/// Every domain as a list row.
	pub fn rows(&self) -> Vec<DomainRow> {
		self.views.iter().map(DomainView::row).collect()
	}

	/// The domain `name`, matched without regard to ASCII case, reported
	/// under the spelling the caller gave. `None` when no hosted domain
	/// matches: the name is compared as given, so a trailing dot, a Unicode
	/// spelling of an A-label or surrounding space does not match.
	pub fn view(&self, name: &str) -> Option<DomainView> {
		self.views
			.iter()
			.find(|view| view.domain.eq_ignore_ascii_case(name))
			.map(|view| DomainView {
				domain: name.to_string(),
				..view.clone()
			})
	}
}

/// Whether `domain` is in `list`, without regard to ASCII case.
fn listed(list: &[String], domain: &str) -> bool {
	list.iter().any(|entry| entry.eq_ignore_ascii_case(domain))
}

/// Whether the address `address` is in `domain`. An address that does not
/// parse is in no domain.
fn in_domain(address: &str, domain: &str) -> bool {
	crate::smtp::address::Address::parse(address)
		.map(|parsed| parsed.domain().eq_ignore_ascii_case(domain))
		.unwrap_or(false)
}

fn view_of(config: &Config, roles: &Roles, domain: &str) -> DomainView {
	let aliases_to = config
		.domain_aliases
		.iter()
		.filter(|(_, target)| target.eq_ignore_ascii_case(domain))
		.map(|(alias, _)| alias.clone())
		.collect();
	let aliases_from = config
		.domain_aliases
		.iter()
		.filter(|(alias, _)| alias.eq_ignore_ascii_case(domain))
		.map(|(_, target)| target.clone())
		.collect();
	let accounts = config
		.accounts
		.iter()
		.flat_map(|account| account.addresses.iter())
		.filter(|address| in_domain(address, domain))
		.cloned()
		.collect();
	let aliases = config
		.alias
		.iter()
		.filter(|alias| in_domain(&alias.address, domain))
		.map(|alias| alias.address.clone())
		.collect();
	let key = domain.to_ascii_lowercase();
	DomainView {
		domain: domain.to_string(),
		enabled: !listed(&config.disabled_domains, domain),
		role: roles.of_name(domain).name(),
		quota: config.domain_quotas.get(&key).copied(),
		submission_rate: config.domain_submission_limits.get(&key).copied(),
		aliases_to,
		aliases_from,
		accounts,
		aliases,
	}
}

#[cfg(test)]
mod tests;
