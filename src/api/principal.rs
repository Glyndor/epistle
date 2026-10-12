//! The principal a JMAP or `/api/v1/send` request acts on behalf of.
//!
//! The bearer-token middleware authenticates a *credential*, not an account:
//! it tells us the request came from the configured token, from a labeled
//! API key, or (in the future) from a user OAuth token. What it does not yet
//! tell us is which account the credential is allowed to act on. The
//! `Principal` enum fills that gap: a single value derived from the matched
//! credential, then consulted by every JMAP method, the upload/download URLs,
//! the WebSocket dispatch and `/api/v1/send` to decide whether the
//! `accountId` in the request is one the caller may reach.
//!
//! Three variants cover the surface today:
//!
//! - `Admin`: the configured static token, or a key with no `domains` field
//!   and no `account` field. Acts on any account.
//! - `Domains(Vec<String>)`: a labeled API key that declared one or more
//!   `domains`. Acts only on accounts whose addresses all live inside the
//!   declared set.
//! - `Account(String)`: a credential that belongs to one account — a
//!   per-user OAuth token once such a credential type is wired into the
//!   bearer middleware, or an API key with `account = "<name>"`. Acts only
//!   on that one account.
//!
//! Refusals surface as the JMAP `accountNotFound` (or HTTP 404 on
//! upload/download) so the existence of other accounts is not revealed.

use super::api_keys::ApiKey;
use super::state::{ApiState, MatchedAuth};

/// What a credential is allowed to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
	/// Every account. The configured static token and any key without a
	/// `domains` or `account` declaration.
	Admin,
	/// Only accounts whose addresses all sit inside this set (case-folded
	/// DNS domains, the same way [`crate::api::domain_scope::DomainScope`]
	/// treats them). An account straddling the boundary is out of scope.
	Domains(Vec<String>),
	/// Exactly one account. Refused to every other account, even if the
	/// account shares domains with the requester.
	Account(String),
}

impl Principal {
	/// Resolve the principal carried by `auth`. The configured static token
	/// is `Admin`; an API key without an `account` field is `Admin` (legacy
	/// behaviour preserved) or `Domains(domains)` when it declares some.
	/// A key with `account = "<name>"` is `Account(name)`.
	///
	/// Fail-closed: a token that matched the middleware but matches no key
	/// here (the running state was swapped out from under us, or the
	/// middleware added a credential kind this code does not yet know)
	/// becomes `Admin`. That widens the read to whatever the static token
	/// would do, which is the behaviour the middleware itself used before
	/// any API key was added.
	pub fn for_token(state: &ApiState, auth: &MatchedAuth) -> Principal {
		let Some(token) = auth.token.as_deref() else {
			// The middleware never lets an unauthenticated request reach a
			// handler, so the only way we get here is a bug in the wiring.
			// Refuse to widen to Admin.
			return Principal::Domains(Vec::new());
		};
		if state.is_configured_token(token) {
			return Principal::Admin;
		}
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		let keys = state.api_keys().snapshot();
		keys.iter()
			.find(|key| key.admits_any(token, auth.client_ip, now, &[]))
			.map(Principal::of_key)
			.unwrap_or(Principal::Admin)
	}

	/// The principal carried by an [`ApiKey`]. An `account` declaration
	/// narrows the principal to that account; an empty `domains` is `Admin`;
	/// a non-empty `domains` is `Domains(domains)`. Both empty is the
	/// legacy un-confined key.
	pub fn of_key(key: &ApiKey) -> Principal {
		if let Some(account) = key.account.as_deref()
			&& !account.is_empty()
		{
			return Principal::Account(account.to_string());
		}
		if key.domains.is_empty() {
			Principal::Admin
		} else {
			Principal::Domains(key.domains.iter().map(|d| d.to_ascii_lowercase()).collect())
		}
	}

	/// Whether `account` (with `addresses` as its full address set) is
	/// inside the principal's reach. An empty address set is treated
	/// strictly: an `Account(name)` allows the matching name and nothing
	/// else, a `Domains(_)` rejects the empty set (nothing to place it in
	/// a tenant), and `Admin` admits anything.
	pub fn admits_account(&self, name: &str, addresses: &[String]) -> bool {
		match self {
			Principal::Admin => true,
			Principal::Account(own) => own == name,
			Principal::Domains(domains) => {
				// Mirror the same fail-closed reading as
				// `DomainScope::admits_account`: every address must be in
				// scope, and an account with no addresses is out of scope.
				if addresses.is_empty() {
					return false;
				}
				addresses.iter().all(|address| {
					address.rsplit_once('@').is_some_and(|(_, domain)| {
						let lower = domain.to_ascii_lowercase();
						domains.iter().any(|d| d == &lower)
					})
				})
			}
		}
	}
}

#[cfg(test)]
#[path = "principal_tests.rs"]
mod tests;
