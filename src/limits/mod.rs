//! Caps per scope, resolved for one account or domain.
//!
//! The scopes, widest first, are the server (`[limits]`), the tenant that
//! owns the domain, the domain and the account; each `[[limit_scope]]` entry
//! configures one of the last three. A scope that sets nothing leaves the
//! wider one's value, `"unlimited"` sets no cap of its own, and a number caps.
//! The resolution takes the strictest number of every scope in reach, so a
//! narrower scope can tighten what a wider one allows and never loosen it;
//! the configuration load refuses an entry that tries, and this resolution
//! holds even when something got past the load.
//!
//! An account whose addresses sit in several domains gets the strictest cap
//! of any of them. With nothing configured the only cap is the one that was
//! always there: 50 OAuth refresh families per account.

use std::collections::HashMap;

mod error;
mod gate;
mod reach;

pub use error::LimitReached;
pub use gate::Gate;
pub(crate) use reach::{Reach, key};

use crate::config::{Caps, Config, Limit, SessionsWhenFull};

/// A thing an account, a domain or a message may not have too many of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
	/// Bytes in one message.
	MessageSize,
	/// Addresses one account holds.
	Addresses,
	/// Aliases in one domain, lists included.
	Aliases,
	/// Mailing lists in one domain.
	Lists,
	/// Members of one alias or list.
	ListMembers,
	/// API keys bound to one account.
	ApiKeys,
	/// App passwords of one account.
	AppPasswords,
	/// Refresh-token families of one account.
	Sessions,
}

/// How many refresh families an account may hold when nothing says otherwise.
pub const DEFAULT_SESSIONS: u64 = 50;

impl Kind {
	/// Every kind.
	pub const ALL: [Kind; 8] = [
		Kind::MessageSize,
		Kind::Addresses,
		Kind::Aliases,
		Kind::Lists,
		Kind::ListMembers,
		Kind::ApiKeys,
		Kind::AppPasswords,
		Kind::Sessions,
	];

	/// The configuration key that sets this cap.
	pub fn key(self) -> &'static str {
		match self {
			Kind::MessageSize => "max_message_size",
			Kind::Addresses => "max_addresses_per_account",
			Kind::Aliases => "max_aliases_per_domain",
			Kind::Lists => "max_lists_per_domain",
			Kind::ListMembers => "max_members_per_list",
			Kind::ApiKeys => "max_api_keys_per_account",
			Kind::AppPasswords => "max_app_passwords_per_account",
			Kind::Sessions => "max_sessions_per_account",
		}
	}

	/// The value `caps` sets for this kind, if any.
	pub fn pick(self, caps: &Caps) -> Option<Limit> {
		match self {
			Kind::MessageSize => caps.max_message_size,
			Kind::Addresses => caps.max_addresses_per_account,
			Kind::Aliases => caps.max_aliases_per_domain,
			Kind::Lists => caps.max_lists_per_domain,
			Kind::ListMembers => caps.max_members_per_list,
			Kind::ApiKeys => caps.max_api_keys_per_account,
			Kind::AppPasswords => caps.max_app_passwords_per_account,
			Kind::Sessions => caps.max_sessions_per_account,
		}
	}

	/// The server scope's value: the configured one, else the cap that
	/// existed before the setting did.
	pub fn server_value(self, server: &Caps) -> Option<Limit> {
		self.pick(server).or(match self {
			Kind::Sessions => Some(Limit::Max(DEFAULT_SESSIONS)),
			_ => None,
		})
	}

	/// What the cap counts, for the refusal.
	pub(crate) fn noun(self) -> &'static str {
		match self {
			Kind::MessageSize => "bytes in a message",
			Kind::Addresses => "addresses per account",
			Kind::Aliases => "aliases per domain",
			Kind::Lists => "mailing lists per domain",
			Kind::ListMembers => "members per alias or list",
			Kind::ApiKeys => "API keys per account",
			Kind::AppPasswords => "app passwords per account",
			Kind::Sessions => "sessions per account",
		}
	}

	/// How to make room, for the refusal.
	pub(crate) fn how_to_free_room(self) -> &'static str {
		match self {
			Kind::MessageSize => "send a smaller message",
			Kind::Addresses => "remove an address",
			Kind::Aliases | Kind::Lists => "remove one",
			Kind::ListMembers => "remove a member",
			Kind::ApiKeys => "revoke an API key",
			Kind::AppPasswords => "remove an app password",
			Kind::Sessions => "sign out of a session",
		}
	}
}

/// Whose cap is asked for: the domains it reaches and, when there is one,
/// the account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Target {
	/// The domains in reach, as written. An account with addresses in
	/// several domains names them all, and the strictest cap applies.
	pub domains: Vec<String>,
	/// The account, when the cap is the account's.
	pub account: Option<String>,
}

impl Target {
	/// A domain.
	pub fn domain(domain: &str) -> Self {
		Self {
			domains: vec![domain.to_string()],
			account: None,
		}
	}

	/// An account and the domains of its addresses.
	pub fn account(account: &str, domains: Vec<String>) -> Self {
		Self {
			domains,
			account: Some(account.to_string()),
		}
	}
}

/// The cap in force and the scope that set it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cap {
	/// The most there may be.
	pub value: u64,
	/// The scope whose value this is, for the refusal and the log:
	/// `the server`, `tenant acme`, `domain example.org`, `account alice`.
	pub set_by: String,
}

/// Every scope of the configuration.
#[derive(Clone, Debug, Default)]
pub struct Limits {
	server: Caps,
	tenants: HashMap<String, Caps>,
	domains: HashMap<String, Caps>,
	accounts: HashMap<String, Caps>,
	reach: Reach,
	/// The server's `max_message_size`; `None` when the limits were built
	/// without a configuration, which caps no message.
	message_size: Option<u64>,
}

impl Limits {
	/// The scopes `config` declares.
	pub fn from_config(config: &Config) -> Self {
		let mut limits = Self {
			server: config.limits.clone(),
			reach: Reach::from_config(config),
			message_size: Some(match config.max_message_size {
				None | Some(0) => crate::smtp::session::MAX_MESSAGE_SIZE as u64,
				Some(size) => size.max(crate::smtp::session::MIN_MESSAGE_SIZE as u64),
			}),
			..Self::default()
		};
		for scope in &config.limit_scopes {
			if let Some(tenant) = &scope.tenant {
				limits.tenants.insert(tenant.clone(), scope.caps.clone());
			} else if let Some(domain) = &scope.domain {
				limits.domains.insert(key(domain), scope.caps.clone());
			} else if let Some(account) = &scope.account {
				limits
					.accounts
					.insert(account.to_ascii_lowercase(), scope.caps.clone());
			}
		}
		limits
	}

	/// The scopes `config` declares, shared between the stores and listeners
	/// that enforce them.
	pub fn shared(config: &Config) -> std::sync::Arc<Self> {
		std::sync::Arc::new(Self::from_config(config))
	}

	/// `domain` as the scopes see it: lower case, a domain alias taken to the
	/// domain it delivers to.
	pub fn scope_domain(&self, domain: &str) -> String {
		self.reach.hosted(domain)
	}

	/// The same scopes with the server's message size set, for the tests
	/// and for callers that build the limits without a configuration.
	pub fn with_message_size(mut self, bytes: u64) -> Self {
		self.message_size = Some(bytes);
		self
	}

	/// The scopes in reach of one domain of `target`, widest first, each
	/// with the name it is reported under.
	fn layers<'a>(
		&'a self,
		domain: Option<&str>,
		account: Option<&str>,
	) -> Vec<(&'a Caps, String)> {
		let mut layers = vec![(&self.server, "the server".to_string())];
		if let Some(domain) = domain {
			let domain = self.reach.hosted(domain);
			if let Some(name) = self.reach.tenant(&domain)
				&& let Some(caps) = self.tenants.get(name)
			{
				layers.push((caps, format!("tenant {name}")));
			}
			if let Some(caps) = self.domains.get(&domain) {
				layers.push((caps, format!("domain {domain}")));
			}
		}
		if let Some(account) = account
			&& let Some(caps) = self.accounts.get(&account.to_ascii_lowercase())
		{
			layers.push((caps, format!("account {account}")));
		}
		layers
	}

	/// The strictest cap of one chain of scopes.
	fn fold(&self, kind: Kind, layers: &[(&Caps, String)]) -> Option<Cap> {
		let mut cap = match kind {
			Kind::MessageSize => self.message_size.map(|value| Cap {
				value,
				set_by: "the server".into(),
			}),
			_ => match kind.server_value(&self.server) {
				Some(Limit::Max(value)) => Some(Cap {
					value,
					set_by: "the server".into(),
				}),
				_ => None,
			},
		};
		for (caps, name) in layers.iter().skip(1) {
			if let Some(Limit::Max(value)) = kind.pick(caps)
				&& cap.as_ref().is_none_or(|current| value < current.value)
			{
				cap = Some(Cap {
					value,
					set_by: name.clone(),
				});
			}
		}
		cap
	}

	/// The cap on `kind` for `target`, or `None` when nothing caps it.
	/// A message size always has one: the server's.
	pub fn resolve(&self, kind: Kind, target: &Target) -> Option<Cap> {
		let account = target.account.as_deref();
		let chains: Vec<Vec<(&Caps, String)>> = if target.domains.is_empty() {
			vec![self.layers(None, account)]
		} else {
			target
				.domains
				.iter()
				.map(|domain| self.layers(Some(domain), account))
				.collect()
		};
		chains
			.iter()
			.filter_map(|chain| self.fold(kind, chain))
			.min_by_key(|cap| cap.value)
	}

	/// Whether one more of `kind` fits when `current` exist already.
	/// `subject` names whose count it is (`account alice`, `domain
	/// example.org`), for the refusal.
	pub fn admit(
		&self,
		kind: Kind,
		target: &Target,
		current: usize,
		subject: &str,
	) -> Result<(), LimitReached> {
		self.admit_total(kind, target, current.saturating_add(1), subject)
	}

	/// Whether `total` of `kind` fit, for a write that adds several at once.
	pub fn admit_total(
		&self,
		kind: Kind,
		target: &Target,
		total: usize,
		subject: &str,
	) -> Result<(), LimitReached> {
		match self.resolve(kind, target) {
			Some(cap) if total as u64 > cap.value => Err(LimitReached {
				kind,
				cap,
				subject: subject.to_string(),
				current: total as u64,
			}),
			_ => Ok(()),
		}
	}

	/// Whether a message of `size` bytes fits what `target` may send or
	/// receive. `subject` names whose cap it is, for the refusal.
	pub fn admit_message(
		&self,
		target: &Target,
		size: u64,
		subject: &str,
	) -> Result<(), LimitReached> {
		match self.resolve(Kind::MessageSize, target) {
			Some(cap) if size > cap.value => Err(LimitReached {
				kind: Kind::MessageSize,
				cap,
				subject: subject.to_string(),
				current: size,
			}),
			_ => Ok(()),
		}
	}

	/// What an account at its session cap does: the most specific scope
	/// that says wins, and the server default is to end the oldest.
	pub fn sessions_when_full(&self, target: &Target) -> SessionsWhenFull {
		let account = target.account.as_deref();
		let domain = target.domains.first().map(String::as_str);
		self.layers(domain, account)
			.iter()
			.rev()
			.find_map(|(caps, _)| caps.sessions_when_full)
			.unwrap_or_default()
	}

	/// Whether nothing is configured.
	pub fn is_inert(&self) -> bool {
		self.server.is_empty()
			&& self.tenants.is_empty()
			&& self.domains.is_empty()
			&& self.accounts.is_empty()
	}
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
