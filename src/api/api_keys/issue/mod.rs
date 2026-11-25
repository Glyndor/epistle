//! The rules for making an API key, which `epistle api-key create` and
//! `POST /api/v1/keys` both run.
//!
//! A key can be made by the operator at a terminal, who may make any key the
//! rules allow, or by another key, which may make only a key that reaches no
//! further than itself ([`Caller`]): fewer scopes, no more domains, a network
//! no wider, an expiry no later. Without that, a key with the `key` scope
//! would be a way to a key with every scope.

use crate::api::api_keys::{Scope, grants};
use crate::cidr::Cidr;

mod reach;

pub use reach::{Caller, Reach};

/// Most domains one key may be confined to.
pub const MAX_DOMAINS: usize = 32;
/// Most keys the file may hold when a key makes one.
pub const MAX_KEYS_BY_KEY: usize = 500;

/// What a new key is asked to be.
#[derive(Debug, Clone, Default)]
pub struct Request {
	/// The label.
	pub label: String,
	/// Expiry as epoch seconds; `None` never expires.
	pub expires_at: Option<u64>,
	/// One network the client must come from.
	pub ip_cidr: Option<String>,
	/// The scopes, spelled as `api_keys.toml` spells them.
	pub scopes: Vec<String>,
	/// The domains the key is confined to; empty reaches every domain.
	pub domains: Vec<String>,
	/// The one account the key is bound to.
	pub account: Option<String>,
}

/// Why a request is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
	/// The request is not one that makes sense: a bad label, no scope, a
	/// network that does not parse, an account that does not exist.
	Invalid(String),
	/// The request is well formed and the rules do not allow it.
	Policy(String),
	/// The request asks for more than the key that makes it has.
	Escalation(String),
}

impl std::fmt::Display for Refusal {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Refusal::Invalid(text) | Refusal::Policy(text) | Refusal::Escalation(text) => {
				f.write_str(text)
			}
		}
	}
}

/// What the rules need to know of the world.
pub trait World {
	/// Whether `name` is an account on this server.
	fn account_known(&self, name: &str) -> bool;
	/// Every address of the account `name`.
	fn account_addresses(&self, name: &str) -> Vec<String>;
	/// Whether `domain` is hosted here. The command answers yes to every
	/// domain: the operator writes the file, and a domain may come before it
	/// is hosted.
	fn hosts(&self, domain: &str) -> bool;
}

/// Scopes only the operator of the whole server may hand to a key bound to an
/// account or confined to domains: they act on the server, not on a tenant.
const SERVER_SCOPES: [&str; 2] = ["ban", "health"];

/// Why an account-bound key may not hold what `scopes` names, if it may not:
/// SCIM, the aliases, the bans, the health routes and the keys manage the
/// server or accounts from outside, and the management scopes open routes that
/// have no "own account". `api-key create`, `api-key set` and
/// `POST /api/v1/keys` ask this one question.
pub fn bound_refusal(scopes: &[String]) -> Option<&'static str> {
	let names = |wanted: &[&str]| scopes.iter().any(|name| wanted.contains(&name.as_str()));
	if names(&["scim", "alias", "ban", "health", "key"]) {
		Some(
			"account-bound API keys cannot hold the scim, alias, ban, health or key scope (all are administrative)",
		)
	} else if names(&["manage:read", "manage:write"]) {
		Some(
			"account-bound API keys cannot hold the manage:read or manage:write scope (both are administrative)",
		)
	} else {
		None
	}
}

/// Check `request`. With a `caller`, the key it asks for may not reach
/// further than the caller does. The domains it names must be hosted here
/// whoever asks (the command's `World` says they all are).
pub fn check(request: &Request, caller: Option<&Caller>, world: &dyn World) -> Result<(), Refusal> {
	if let Some(problem) = crate::util::label_rule::problem(&request.label) {
		return Err(Refusal::Invalid(problem.to_string()));
	}
	if request.scopes.is_empty() {
		return Err(Refusal::Invalid(
			"--scope is required (repeat to grant more than one: manage:read, manage:write, mail:read, mail:write, send, scim, alias, ban, health, key)"
				.to_string(),
		));
	}
	// The scopes the key would hold, by the one reading of both vocabularies:
	// `read` and `write` mean both halves, or the mail half for a key bound to
	// an account.
	let (_, grants) = grants::stored_form(&request.scopes, request.account.is_some())
		.map_err(|error| Refusal::Invalid(error.to_string()))?;
	let cidr = match &request.ip_cidr {
		Some(spec) => Some(Cidr::parse(spec).ok_or_else(|| Refusal::Invalid(Cidr::refusal(spec)))?),
		None => None,
	};
	if request.domains.len() > MAX_DOMAINS {
		return Err(Refusal::Invalid(format!(
			"a key is confined to at most {MAX_DOMAINS} domains"
		)));
	}
	if let Some(name) = &request.account {
		if !world.account_known(name) {
			return Err(Refusal::Invalid(format!(
				"--account {name}: no such account"
			)));
		}
		if let Some(refusal) = bound_refusal(&request.scopes) {
			return Err(Refusal::Policy(refusal.to_string()));
		}
	}
	if !request.domains.is_empty()
		&& request
			.scopes
			.iter()
			.any(|scope| SERVER_SCOPES.contains(&scope.as_str()))
	{
		return Err(Refusal::Policy(
			"the ban and health scopes cover the whole server and cannot be confined with --domain"
				.to_string(),
		));
	}
	if let Some(domain) = request
		.domains
		.iter()
		.find(|domain| !world.hosts(&domain.to_ascii_lowercase()))
	{
		return Err(Refusal::Invalid(format!(
			"{domain} is not a domain this server hosts"
		)));
	}
	let Some(caller) = caller else {
		return Ok(());
	};
	let wanted = Reach {
		scopes: Some(
			grants
				.iter()
				.filter_map(|scope| scope.parse::<Scope>().ok())
				.collect(),
		),
		domains: (!request.domains.is_empty()).then(|| {
			request
				.domains
				.iter()
				.map(|domain| domain.to_ascii_lowercase())
				.collect()
		}),
		account_addresses: request
			.account
			.as_deref()
			.map(|name| world.account_addresses(name)),
		ip_cidr: cidr,
		expires_at: request.expires_at,
	};
	caller.reach().covers(&wanted).map_err(Refusal::Escalation)
}

#[cfg(test)]
mod tests;
