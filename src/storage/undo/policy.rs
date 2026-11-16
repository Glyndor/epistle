//! How long a submission is held, resolved for one account.
//!
//! The scopes, widest first, are the server (the `[queue.undo_send]` delay),
//! the tenant that owns the account's domain, that domain and the account.
//! The most specific scope that names the account decides, and a delay of
//! `0` turns the hold off for it. Whatever is decided is capped at
//! `max_secs`: the ceiling holds even if a scope were somehow above it.

use std::collections::HashMap;

use crate::config::Config;
use crate::smtp::directory::Directory;

/// `domain` as the policy keys it: lower case, no trailing dot.
fn key(domain: &str) -> String {
	domain.trim_end_matches('.').to_ascii_lowercase()
}

/// The delays of every scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoPolicy {
	server: u32,
	max: u32,
	tenants: HashMap<String, u32>,
	domains: HashMap<String, u32>,
	accounts: HashMap<String, u32>,
	/// Hosted domain to the name of the tenant that owns it.
	tenant_of: HashMap<String, String>,
	/// Domain alias to the domain it delivers to.
	domain_aliases: HashMap<String, String>,
}

impl UndoPolicy {
	/// The policy `config` declares.
	pub fn from_config(config: &Config) -> Self {
		let section = &config.queue.undo_send;
		let mut policy = Self {
			server: section.delay_secs,
			max: section.max_secs,
			domain_aliases: config
				.domain_aliases
				.iter()
				.map(|(alias, target)| (key(alias), key(target)))
				.collect(),
			..Self::default()
		};
		for tenant in &config.tenants {
			if let Some(name) = &tenant.name {
				for domain in &tenant.domains {
					policy.tenant_of.insert(key(domain), name.clone());
				}
			}
		}
		for scope in &section.scope {
			match scope.target() {
				Some(("tenant", name)) => {
					policy.tenants.insert(name.to_string(), scope.delay_secs);
				}
				Some(("domain", name)) => {
					policy.domains.insert(key(name), scope.delay_secs);
				}
				Some((_, name)) => {
					policy.accounts.insert(name.to_string(), scope.delay_secs);
				}
				None => {}
			}
		}
		policy
	}

	/// Whether no scope holds anything, so the sink need not be put in front
	/// of the submission path at all.
	pub fn is_off(&self) -> bool {
		self.max == 0
			|| (self.server == 0
				&& self.tenants.values().all(|delay| *delay == 0)
				&& self.domains.values().all(|delay| *delay == 0)
				&& self.accounts.values().all(|delay| *delay == 0))
	}

	/// Seconds to hold what `account` submits; `0` holds nothing. The
	/// account's domain is the one all its addresses sit in: an account
	/// spread over several domains has none, and only its own scope and the
	/// server's apply to it.
	pub fn delay_for(&self, directory: &Directory, account: &str) -> u32 {
		let owner = crate::webhook::account_owner(directory, account).map(|domain| {
			let domain = key(&domain);
			self.domain_aliases.get(&domain).cloned().unwrap_or(domain)
		});
		self.delay_in(account, owner.as_deref())
	}

	/// [`delay_for`](Self::delay_for) when the account's domain is known.
	pub(super) fn delay_in(&self, account: &str, domain: Option<&str>) -> u32 {
		let chosen = self
			.accounts
			.get(account)
			.or_else(|| domain.and_then(|domain| self.domains.get(domain)))
			.or_else(|| {
				domain
					.and_then(|domain| self.tenant_of.get(domain))
					.and_then(|tenant| self.tenants.get(tenant))
			})
			.copied()
			.unwrap_or(self.server);
		chosen.min(self.max)
	}
}
