//! Antispam settings per scope, resolved for one recipient or sender.
//!
//! The scopes, widest first, are the server (the top-level sections), the
//! tenant that owns the domain, the domain and the account. Each
//! `[[antispam_scope]]` entry configures one of the last three. The rules
//! are the same for every setting that follows them:
//!
//! - **Deny lists add up.** An entry on any scope in reach refuses, and no
//!   allow entry anywhere lifts it, so a scope can add a refusal but never
//!   undo the server's.
//! - **Allow lists add up** too, and only matter when no deny entry matches.
//! - **Attachment settings only tighten.** The configuration load refuses
//!   a scope that is weaker than the server; the resolution takes the
//!   strictest value of every scope in reach regardless.
//!
//! A message with several recipients is judged by all of them: a sender is
//! refused for the recipient it is refused for and no other, a sender is
//! only favoured when every recipient favours it, and attachment settings
//! are the strictest of any recipient.

use std::collections::HashMap;

mod checks;
mod forwarding;
mod numbers;

use crate::antispam::attachments::policy::Overlay;
use crate::antispam::sender_lists::Matcher;
pub use checks::Checks;
use forwarding::ForwardOverrides;
pub use forwarding::ForwardSettings;
use numbers::Overrides;
pub use numbers::SpamNumbers;

use crate::config::{AntispamScope, CheckScope, Config, SenderLists};

/// Whose settings apply: a domain and, when one account owns the address,
/// that account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
	/// The domain of the address, as written, lower case.
	pub domain: String,
	/// The account the address belongs to, when there is one.
	pub account: Option<String>,
}

impl Target {
	/// The targets of one recipient address in `domain`: one per account the
	/// address delivers to (a multi-target alias has several), so every
	/// member's scope applies; or the domain alone when no account is known.
	pub fn of_recipient(domain: &str, accounts: &[String]) -> Vec<Self> {
		if accounts.is_empty() {
			return vec![Self {
				domain: domain.to_string(),
				account: None,
			}];
		}
		accounts
			.iter()
			.map(|account| Self {
				domain: domain.to_string(),
				account: Some(account.clone()),
			})
			.collect()
	}
}

/// The settings of one scope.
#[derive(Clone, Debug, Default)]
struct Layer {
	allow: Matcher,
	deny: Matcher,
	deny_recipients: Matcher,
	attachments: Overlay,
	numbers: Overrides,
	checks: CheckScope,
	forward: ForwardOverrides,
}

impl Layer {
	fn from_lists(lists: &SenderLists) -> Self {
		Self {
			allow: Matcher::new(&lists.allow),
			deny: Matcher::new(&lists.deny),
			deny_recipients: Matcher::new(&lists.deny_recipients),
			attachments: Overlay::default(),
			numbers: Overrides::default(),
			checks: CheckScope::default(),
			forward: ForwardOverrides::default(),
		}
	}

	fn from_scope(scope: &AntispamScope) -> Self {
		Self {
			attachments: Overlay::from_scope(&scope.attachments),
			numbers: Overrides {
				junk_at: scope.bayes_junk_at,
				reject_at: scope.bayes_reject_at,
				greylist_delay_secs: scope.greylist_delay_secs,
				first_time_delay_secs: scope.first_time_sender_delay_secs,
			},
			checks: scope.checks,
			forward: ForwardOverrides {
				policy: scope.forward_policy,
				per_min: scope.forward_per_min,
			},
			..Self::from_lists(&scope.senders)
		}
	}

	fn is_inert(&self) -> bool {
		self.allow.is_empty()
			&& self.deny.is_empty()
			&& self.deny_recipients.is_empty()
			&& self.attachments.is_empty()
			&& self.numbers.is_empty()
			&& self.checks.is_empty()
			&& self.forward.is_empty()
	}
}

/// Every scope of the configuration.
#[derive(Clone, Debug, Default)]
pub struct Scopes {
	server: Layer,
	tenants: HashMap<String, Layer>,
	domains: HashMap<String, Layer>,
	accounts: HashMap<String, Layer>,
	/// Hosted domain to the name of the tenant that owns it.
	tenant_of: HashMap<String, String>,
	/// Domain alias to the domain it delivers to.
	domain_aliases: HashMap<String, String>,
}

/// `domain` as the scopes key it: lower case, no trailing dot.
fn key(domain: &str) -> String {
	domain.trim_end_matches('.').to_ascii_lowercase()
}

impl Scopes {
	/// The scopes `config` declares.
	pub fn from_config(config: &Config) -> Self {
		let mut scopes = Self {
			server: Layer::from_lists(&config.antispam.senders),
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
					scopes.tenant_of.insert(key(domain), name.clone());
				}
			}
		}
		for scope in &config.antispam_scopes {
			let layer = Layer::from_scope(scope);
			if let Some(tenant) = &scope.tenant {
				scopes.tenants.insert(tenant.clone(), layer);
			} else if let Some(domain) = &scope.domain {
				scopes.domains.insert(key(domain), layer);
			} else if let Some(account) = &scope.account {
				scopes.accounts.insert(account.clone(), layer);
			}
		}
		scopes
	}

	/// Whether nothing is configured, so callers can skip the lookups.
	pub fn is_inert(&self) -> bool {
		self.server.is_inert()
			&& self.tenants.values().all(Layer::is_inert)
			&& self.domains.values().all(Layer::is_inert)
			&& self.accounts.values().all(Layer::is_inert)
	}

	/// The scopes in reach of `target`, widest first.
	fn layers<'a>(&'a self, target: &Target) -> impl Iterator<Item = &'a Layer> {
		let domain = key(&target.domain);
		let domain = self.domain_aliases.get(&domain).cloned().unwrap_or(domain);
		let tenant = self
			.tenant_of
			.get(&domain)
			.and_then(|name| self.tenants.get(name));
		let account = target
			.account
			.as_deref()
			.and_then(|name| self.accounts.get(name));
		[
			Some(&self.server),
			tenant,
			self.domains.get(&domain),
			account,
		]
		.into_iter()
		.flatten()
	}

	/// Whether mail from `sender` to `target` is refused: a deny entry of
	/// any scope in reach names the sender.
	pub fn refuses_sender(&self, sender: &str, target: &Target) -> bool {
		self.layers(target).any(|layer| layer.deny.matches(sender))
	}

	/// Whether an allow entry of a scope in reach names `sender` and no
	/// deny entry does. This is only the list's answer: whether the server
	/// verified the sender is the caller's to check.
	pub fn favours_sender(&self, sender: &str, target: &Target) -> bool {
		!self.refuses_sender(sender, target)
			&& self.layers(target).any(|layer| layer.allow.matches(sender))
	}

	/// Whether the account `from` may not send to `recipient`.
	pub fn refuses_recipient(&self, recipient: &str, from: &Target) -> bool {
		self.layers(from)
			.any(|layer| layer.deny_recipients.matches(recipient))
	}

	/// The attachment settings of every scope in reach of any of
	/// `targets`, merged to the strictest.
	pub fn attachment_overlay(&self, targets: &[Target]) -> Overlay {
		let mut merged = Overlay::default();
		for target in targets {
			for layer in self.layers(target) {
				merged.tighten(&layer.attachments);
			}
		}
		merged
	}
}

#[cfg(test)]
mod tests;
