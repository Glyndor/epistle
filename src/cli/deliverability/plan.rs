//! What one test run sends, and the refusals that come before anything is
//! written: the account, the address it sends from and the destination.

use crate::config::Config;
use crate::directory_store::AccountStore;
use crate::util::address_reason;

/// Exit code of a usage error: a name that does not exist, an address that is
/// not one.
pub(super) const USAGE: u8 = 2;
/// Exit code of a refusal by policy.
pub(super) const POLICY: u8 = 3;

/// A run that stops before it sends: the exit code and what to tell the
/// operator.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Refusal {
	pub code: u8,
	pub message: String,
}

impl Refusal {
	fn usage(message: impl Into<String>) -> Self {
		Self {
			code: USAGE,
			message: message.into(),
		}
	}

	pub(super) fn policy(message: impl Into<String>) -> Self {
		Self {
			code: POLICY,
			message: message.into(),
		}
	}
}

/// The message one run sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Plan {
	/// The account that sends it.
	pub account: String,
	/// The address it is sent from, lower case.
	pub from: String,
	/// The domain of `from`: hosted here, and the one DKIM signs for.
	pub domain: String,
	/// The address the operator named, lower case.
	pub to: String,
}

/// Whether this server hosts `domain`, directly or as an alias domain.
fn hosts(config: &Config, domain: &str) -> bool {
	config
		.domains
		.iter()
		.any(|hosted| hosted.eq_ignore_ascii_case(domain))
		|| config
			.domain_aliases
			.contains_key(&domain.to_ascii_lowercase())
}

/// What the account may do: its addresses, whether it is switched off and
/// whether its sending is on.
fn account_facts(store: &AccountStore, name: &str) -> Option<(Vec<String>, bool, bool)> {
	if let Some(account) = store.dynamic(name) {
		return Some((
			account.addresses,
			account.disabled,
			account.send.unwrap_or(true),
		));
	}
	store.static_view(name).map(|account| {
		(
			account.addresses.clone(),
			false,
			account.send.unwrap_or(true),
		)
	})
}

/// Check the account, its sending address and the destination.
///
/// The destination is the operator's: it is never invented, and it must be
/// outside this server, because mail to a hosted domain is delivered
/// locally and says nothing about what the outside thinks of it.
pub(super) fn resolve(
	config: &Config,
	store: &AccountStore,
	account: &str,
	to: &str,
) -> Result<Plan, Refusal> {
	let to = crate::util::address::normalize(to);
	if let Err(why) = address_reason::parse(&to) {
		return Err(Refusal::usage(format!(
			"the destination is not a valid address: {why}"
		)));
	}
	let (_, to_domain) = to.rsplit_once('@').unwrap_or_default();
	if hosts(config, to_domain) {
		return Err(Refusal::usage(format!(
			"{to_domain} is hosted by this server, so the message would be delivered locally and tell nothing about the outside; name an address elsewhere"
		)));
	}
	let Some((addresses, disabled, sends)) = account_facts(store, account) else {
		return Err(Refusal::usage(format!("no such account: {account}")));
	};
	if disabled {
		return Err(Refusal::policy(format!("account {account} is disabled")));
	}
	if !sends {
		return Err(Refusal::policy(format!(
			"sending is switched off for account {account}"
		)));
	}
	let mut first_foreign = None;
	for address in &addresses {
		let address = crate::util::address::normalize(address);
		if address_reason::parse(&address).is_err() {
			continue;
		}
		let (_, domain) = address.rsplit_once('@').unwrap_or_default();
		if !hosts(config, domain) {
			first_foreign.get_or_insert(domain.to_string());
			continue;
		}
		if !config.domain_role(domain).sends() {
			return Err(Refusal::policy(format!(
				"{domain} does not send mail from this server"
			)));
		}
		return Ok(Plan {
			account: account.to_string(),
			domain: domain.to_string(),
			from: address,
			to,
		});
	}
	Err(Refusal::policy(match first_foreign {
		Some(domain) => format!("{domain} is not a domain this server hosts"),
		None => format!("account {account} has no address to send from"),
	}))
}
