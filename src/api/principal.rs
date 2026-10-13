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
//! - `Domains { domains, credential }`: a labeled API key that declared one
//!   or more `domains`. Acts only on accounts whose addresses all live
//!   inside the declared set. The `credential` is the matched bearer and
//!   peer IP, kept so handlers can re-check scopes against the same key the
//!   middleware matched.
//! - `Account { name, credential }`: a credential that belongs to one
//!   account: an API key with `account = "<name>"`, or a per-user OAuth
//!   token once such a credential type is wired into the bearer middleware.
//!   Acts only on that one account.
//!
//! Refusals surface as the JMAP `accountNotFound` (or HTTP 404 on
//! upload/download) so the existence of other accounts is not revealed.

use super::api_keys::ApiKey;
use super::state::{AccountView, ApiState, MatchedAuth};

/// The bearer that authenticated a request and the peer it came from,
/// kept so a handler can re-check a scope against the same key, under the
/// same `ip_cidr` pin, that the middleware matched.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
	/// The bearer as presented.
	pub token: String,
	/// The peer IP the middleware saw, `None` when the listener does not
	/// report it (an IP-pinned key then never matches, fail-closed).
	pub client_ip: Option<std::net::IpAddr>,
}

impl std::fmt::Debug for Credential {
	// The bearer is a secret: a principal that ends up in a log line or a
	// test failure message must not carry it along.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Credential")
			.field("token", &"<redacted>")
			.field("client_ip", &self.client_ip)
			.finish()
	}
}

/// What a credential is allowed to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
	/// Every account. The configured static token, or a key without a
	/// `domains` or `account` declaration. The `credential` is the matched
	/// bearer when the principal came from a key: it lets scope re-checks
	/// (e.g. a `read`-only key not writing) consult the same key the
	/// middleware matched. `None` for the static token, which admits
	/// every scope by design.
	Admin {
		/// The credential that mapped to this principal, when it came
		/// from a key. `None` for the configured static token.
		credential: Option<Credential>,
	},
	/// Only accounts whose addresses all sit inside this set (case-folded
	/// DNS domains, the same way [`crate::api::domain_scope::DomainScope`]
	/// treats them). An account straddling the boundary is out of scope.
	/// The carried `credential` is the bearer that authenticated, kept so
	/// handlers can re-check scopes against the same key the middleware
	/// matched.
	Domains {
		/// The lowercased DNS domains this principal is allowed to reach.
		domains: Vec<String>,
		/// The credential that mapped to this principal. `None` when the
		/// principal was constructed in a test or by code that did not go
		/// through the bearer middleware.
		credential: Option<Credential>,
	},
	/// Exactly one account. Refused to every other account, even if the
	/// account shares domains with the requester. `credential` carries the
	/// matched bearer, same as [`Self::Domains`].
	Account {
		/// The single account this principal may act on.
		name: String,
		/// The credential that mapped to this principal, when the
		/// principal was resolved from a real credential.
		credential: Option<Credential>,
	},
}

impl Principal {
	/// Resolve the principal carried by `auth`. The configured static token
	/// is `Admin`; an API key without an `account` field is `Admin` (legacy
	/// behaviour preserved) or `Domains(domains)` when it declares some.
	/// A key with `account = "<name>"` is `Account(name)`.
	///
	/// Fail-closed: a token that matched the middleware but matches no key
	/// here (a reload removed the key between the middleware and the
	/// handler, or the middleware learned a credential kind this code does
	/// not know yet) reaches no account and holds no scope. It never falls
	/// back to the reach of the configured token.
	pub fn for_token(state: &ApiState, auth: &MatchedAuth) -> Principal {
		let Some(token) = auth.token.as_deref() else {
			// The middleware never lets an unauthenticated request reach a
			// handler, so the only way we get here is a bug in the wiring.
			// Refuse to widen to Admin.
			return Principal::Domains {
				domains: Vec::new(),
				credential: None,
			};
		};
		// Read from the middleware, which compared the bearer against the
		// configured hash once for the whole request.
		if auth.configured {
			return Principal::Admin { credential: None };
		}
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		// The principal is independent of any specific scope: a key that
		// authenticates the caller is the same key whether the route wants
		// `read`, `write` or `send`. The slice of every scope lets
		// `admits_any` accept any scoped key, the same way the middleware
		// does for the routes that pass coarse-grained path/method
		// inference.
		const EVERY_SCOPE: &[super::api_keys::Scope] = &[
			super::api_keys::Scope::Read,
			super::api_keys::Scope::Write,
			super::api_keys::Scope::Send,
		];
		let credential = Credential {
			token: token.to_string(),
			client_ip: auth.client_ip,
		};
		let keys = state.api_keys().snapshot();
		match keys
			.iter()
			.find(|key| key.admits_any(token, auth.client_ip, now, EVERY_SCOPE))
		{
			Some(key) => Principal::kind_of_key(key).into_principal(Some(credential)),
			None => Principal::Domains {
				domains: Vec::new(),
				credential: Some(credential),
			},
		}
	}

	/// The credential that authenticated, when the principal came from a
	/// key. `None` for the configured static token. Used by
	/// [`crate::api::state::ApiState::require_scope_for_principal`] to
	/// look the same key up again, from the same peer, when re-checking
	/// scopes.
	pub fn credential(&self) -> Option<&Credential> {
		match self {
			Principal::Admin { credential, .. }
			| Principal::Domains { credential, .. }
			| Principal::Account { credential, .. } => credential.as_ref(),
		}
	}

	/// The principal kind carried by an [`ApiKey`], without the bearer
	/// token. An `account` declaration narrows the principal to that
	/// account; an empty `domains` is `Admin`; a non-empty `domains` is
	/// `Domains(domains)`. Both empty is the legacy un-confined key.
	///
	/// A present but empty `account` names no account, so it reaches none:
	/// reading it as "no binding" would widen a key its operator meant to
	/// narrow.
	pub fn kind_of_key(key: &ApiKey) -> PrincipalKind {
		if let Some(account) = key.account.as_deref() {
			return PrincipalKind::Account(account.to_string());
		}
		if key.domains.is_empty() {
			PrincipalKind::Admin
		} else {
			PrincipalKind::Domains(key.domains.iter().map(|d| d.to_ascii_lowercase()).collect())
		}
	}

	/// Whether `account` (with `addresses` as its full address set) is
	/// inside the principal's reach. An empty address set is treated
	/// strictly: an `Account(name)` allows the matching name and nothing
	/// else, a `Domains(_)` rejects the empty set (nothing to place it in
	/// a tenant), and `Admin` admits anything.
	pub fn admits_account(&self, name: &str, addresses: &[String]) -> bool {
		match self {
			Principal::Admin { .. } => true,
			Principal::Account { name: own, .. } => own == name,
			Principal::Domains { domains, .. } => {
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

	/// The list of every account the principal may reach, given the full
	/// directory `accounts`. Used by the JMAP Session resource so a
	/// domain-scoped key does not learn the existence of accounts outside
	/// its tenant.
	pub fn admissible_accounts<'a>(&self, accounts: &'a [AccountView]) -> Vec<&'a AccountView> {
		accounts
			.iter()
			.filter(|account| self.admits_account(&account.name, &account.addresses))
			.collect()
	}
}

/// A [`Principal`] without the bearer token. Used by tests and by code
/// that has a key but not a credential (e.g. admin tooling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
	Admin,
	Domains(Vec<String>),
	Account(String),
}

impl PrincipalKind {
	/// Wrap into a [`Principal`] with the given credential, when the
	/// principal came from a real one. The credential rides on every
	/// variant so scope re-checks have somewhere to look.
	pub fn into_principal(self, credential: Option<Credential>) -> Principal {
		match self {
			PrincipalKind::Admin => Principal::Admin { credential },
			PrincipalKind::Domains(domains) => Principal::Domains {
				domains,
				credential,
			},
			PrincipalKind::Account(name) => Principal::Account { name, credential },
		}
	}
}

#[cfg(test)]
#[path = "principal_tests.rs"]
mod tests;
