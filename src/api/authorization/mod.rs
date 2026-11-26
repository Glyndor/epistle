//! The one place an API credential becomes an allow-or-deny decision.
//!
//! The bearer middleware authenticates a *credential*, not an account: it
//! tells us the request came from the configured token, from a labeled API
//! key, or from a user OAuth token. What it does not tell us
//! is what that credential may act on. This module fills that gap. It
//! resolves the credential into a [`Principal`] once per request and answers
//! every question the routes ask about it.
//!
//! The reach is composed from three restrictions, all read from the same API
//! key snapshot, so one decision never mixes two versions of one key:
//!
//! - the scopes the key holds,
//! - the account the key is bound to,
//! - the domains the key is confined to.
//!
//! A key that declares more than one of them is confined by all of them at
//! once: a key bound to one account *and* confined to some domains reaches
//! only the accounts that satisfy both. An empty or unresolved set never
//! widens a confined key. An account with no addresses carries no evidence of
//! which tenant it belongs to, and a credential that matches no key reaches
//! nothing at all.

use super::api_keys::{ApiKey, Scope};
use super::state::{AccountView, ApiState, MatchedAuth};

/// The bearer that authenticated a request and the peer it came from, kept
/// so a handler can re-check a scope against the same key, under the same
/// `ip_cidr` pin, that the middleware matched.
#[derive(Clone, Eq)]
pub struct Credential {
	/// The bearer as presented.
	pub token: String,
	/// The peer IP the middleware saw, `None` when the listener does not
	/// report it (an IP-pinned key then never matches, fail-closed).
	pub client_ip: Option<std::net::IpAddr>,
}

impl PartialEq for Credential {
	fn eq(&self, other: &Self) -> bool {
		crate::util::constant_time::eq(self.token.as_bytes(), other.token.as_bytes())
			&& self.client_ip == other.client_ip
	}
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
#[derive(Clone, PartialEq, Eq)]
pub struct Principal {
	/// The scopes the key holds. `None` means it holds every scope: the
	/// configured static token, and the legacy key that declares none. An
	/// empty list means it holds none at all.
	scopes: Option<Vec<Scope>>,
	/// The account the key is bound to. `None` when it is not bound to one.
	account: Option<String>,
	/// The domains the key is confined to, lowercased. `None` when the key
	/// declares no domain restriction; an empty list admits no domain.
	domains: Option<Vec<String>>,
	/// The credential that mapped to this principal, when it came from a
	/// key. `None` for the configured static token, which admits every scope
	/// by design.
	credential: Option<Credential>,
	auto_submitted: bool,
	/// The label of the key, when the principal came from one: what an audit
	/// line names so the key that made a change can be told from the others.
	/// Never the bearer.
	label: Option<String>,
}

impl std::fmt::Debug for Principal {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// OAuth account and scope values originate in claims. Keep them out
		// of diagnostics, just as Credential keeps the bearer out.
		f.debug_struct("Principal")
			.field("scopes", &"<redacted>")
			.field("account", &"<redacted>")
			.field("domains", &"<redacted>")
			.field("credential", &self.credential)
			.finish()
	}
}

impl Principal {
	/// Every scope a key can hold, for the places that need to find a key
	/// whatever it holds (a secret that two keys share has no reach).
	pub(crate) const EVERY_SCOPE: &'static [Scope] = &[
		Scope::ManageRead,
		Scope::ManageWrite,
		Scope::MailRead,
		Scope::MailWrite,
		Scope::Send,
		Scope::Scim,
		Scope::Alias,
		Scope::Ban,
		Scope::Health,
	];

	/// An OAuth token always has explicit scopes and exactly one account.
	pub(in crate::api) fn of_oauth(
		account: String,
		scopes: Vec<Scope>,
		credential: Credential,
	) -> Self {
		Self {
			scopes: Some(scopes),
			account: Some(account),
			domains: None,
			credential: Some(credential),
			auto_submitted: false,
			label: None,
		}
	}
	/// The reach of the configured static token: every scope, every account,
	/// every domain.
	pub fn unrestricted() -> Self {
		Principal {
			scopes: None,
			account: None,
			domains: None,
			credential: None,
			auto_submitted: false,
			label: None,
		}
	}

	/// A reach that holds no scope and reaches no account: the answer for a
	/// credential that matched the middleware but matches no key.
	fn unreachable(credential: Option<Credential>) -> Self {
		Principal {
			scopes: Some(Vec::new()),
			account: None,
			domains: Some(Vec::new()),
			credential,
			auto_submitted: false,
			label: None,
		}
	}

	/// The reach a key declares.
	///
	/// A key that declares both an account and domains is confined by both
	/// at once: the account binding and the domain binding are two halves of
	/// one restriction, not one of them replacing the other. An account that
	/// is present but empty names no account, so it reaches none.
	pub fn of_key(key: &ApiKey, credential: Option<Credential>) -> Self {
		// No scope declared is the legacy key: it holds every scope. A scope
		// this build cannot read is a scope the key does not hold, and refusing
		// the whole key is the only fail-closed reading.
		let scopes = key.reach();
		let domains = if key.domains.is_empty() {
			None
		} else {
			Some(
				key.domains
					.iter()
					.map(|domain| domain.to_ascii_lowercase())
					.collect(),
			)
		};
		Principal {
			scopes,
			account: key.account.clone(),
			domains,
			credential,
			auto_submitted: key.auto_submitted,
			label: Some(key.label.clone()),
		}
	}

	/// Resolve the principal carried by `auth`. The configured static token
	/// is unrestricted; a local OAuth token is confined to its subject and
	/// explicit scopes, and an API key carries whatever it declared.
	///
	/// Fail-closed: a token that matched the middleware but matches no key
	/// here (a reload removed the key between the middleware and the
	/// handler, or the middleware learned a credential kind this code does
	/// not know yet) reaches no account and holds no scope. It never falls
	/// back to the reach of the configured token.
	pub fn for_token(state: &ApiState, auth: &MatchedAuth) -> Principal {
		let principal = Self::resolve(state, auth);
		// The restrictions of a key bound to an account apply to every
		// resolution, so that one made after a request's body has arrived is
		// held to what the middleware asked: a route such a key may use, and
		// an account that is still there to act on.
		if principal.bound_account().is_some()
			&& !(auth.account_scoped
				&& crate::api::account_bound::bound_account_is_live(state, &principal))
		{
			return Principal::unreachable(principal.credential);
		}
		principal
	}

	/// The key of `auth` as it is now, without the restrictions that depend on
	/// the route and on the bound account's state, which
	/// [`for_token`](Self::for_token) adds: the middleware asks them itself, to
	/// answer each with its own error.
	pub(crate) fn resolve(state: &ApiState, auth: &MatchedAuth) -> Principal {
		let Some(token) = auth.token.as_deref() else {
			// The middleware never lets an unauthenticated request reach a
			// handler, so the only way we get here is a bug in the wiring.
			// Refuse to widen.
			return Principal::unreachable(None);
		};
		// Read from the middleware, which compared the bearer against the
		// configured hash once for the whole request.
		if auth.configured {
			return Principal::unrestricted();
		}
		if let Some(principal) = state.oauth_principal(token, auth.client_ip) {
			return principal;
		}
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		// The principal is independent of any specific scope: the key that
		// authenticates the caller is the same key whether the route wants
		// `manage:read`, `mail:write`, `send` or `scim`. The scopes it holds ride on the
		// principal, and the route that needs one asks for it.
		let credential = Credential {
			token: token.to_string(),
			client_ip: auth.client_ip,
		};
		let keys = state.api_keys().snapshot();
		let mut matching = keys
			.iter()
			.filter(|key| key.admits_any(token, auth.client_ip, now, Self::EVERY_SCOPE));
		match (matching.next(), matching.next()) {
			// The key has to hold one of the scopes the request was admitted
			// under, now and not as of the middleware: it is read again after
			// the body, and the scopes may have been withdrawn in between.
			(Some(key), None) if key.covers_any(&auth.acceptable_scopes) => {
				Principal::of_key(key, Some(credential))
			}
			// Two keys share the secret, so the one that let the request in
			// cannot be told from the other and no reach is safe to pick.
			_ => Principal::unreachable(Some(credential)),
		}
	}

	/// The label of the key this principal came from, for an audit line.
	pub fn key_label(&self) -> Option<&str> {
		self.label.as_deref()
	}

	/// The domains the credential is confined to, lowercased, or `None` when
	/// it declares no domain restriction.
	pub fn confined_domains(&self) -> Option<&[String]> {
		self.domains.as_deref()
	}

	/// The account the credential is bound to, if any.
	pub fn bound_account(&self) -> Option<&str> {
		self.account.as_deref()
	}

	/// The credential that authenticated, when the principal came from a
	/// key. `None` for the configured static token. Used to look the same
	/// key up again, from the same peer, when the caller identity needs it.
	pub fn credential(&self) -> Option<&Credential> {
		self.credential.as_ref()
	}

	/// Whether mail sent with this credential gets `Auto-Submitted:
	/// auto-generated` when the request omits the header.
	pub fn auto_submitted(&self) -> bool {
		self.auto_submitted
	}

	/// Whether the credential holds `scope`.
	pub fn admits_scope(&self, scope: Scope) -> bool {
		match &self.scopes {
			None => true,
			Some(scopes) => scopes.contains(&scope),
		}
	}

	/// Whether the credential reaches the account `name`, whose complete
	/// address set is `addresses`.
	///
	/// Every restriction applies at once: the account binding and the
	/// domain binding. An account holding one address inside the domains
	/// and another outside it belongs to two tenants at once, so it is out of
	/// reach for a confined key.
	pub fn admits_account(&self, name: &str, addresses: &[String]) -> bool {
		if let Some(own) = &self.account
			&& own != name
		{
			return false;
		}
		self.admits_domains(addresses)
	}

	/// Whether every address in `addresses` sits inside the credential's
	/// domains.
	///
	/// An account-bound credential reaches one account by name, so an
	/// address set on its own says nothing about whether it may act: the
	/// answer is no. The routes that ask about a bare address (the queue,
	/// whose entries carry a sender and no account) therefore refuse it.
	pub fn admits_addresses(&self, addresses: &[String]) -> bool {
		if self.account.is_some() {
			return false;
		}
		self.admits_domains(addresses)
	}

	/// Whether `domain` is inside the credential's domains. Comparison is
	/// case-insensitive, because DNS is.
	pub fn admits_domain(&self, domain: &str) -> bool {
		match &self.domains {
			None => true,
			Some(domains) => {
				let domain = domain.to_ascii_lowercase();
				domains.contains(&domain)
			}
		}
	}

	/// Whether the domain of the single address `address` is inside the
	/// credential's domains. A credential with no domain restriction admits
	/// any sender, and an address with no domain, such as the empty
	/// reverse-path of a bounce, is outside every declared domain.
	pub fn admits_sender(&self, address: &str) -> bool {
		self.admits_domains(&[address.to_string()])
	}

	/// Whether the credential is unrestricted: it declares neither an
	/// account nor a domain, so it reaches every account and every domain.
	///
	/// State every tenant shares has no tenant to filter it by, so only an
	/// unrestricted credential may see it.
	pub fn is_unrestricted(&self) -> bool {
		self.account.is_none() && self.domains.is_none()
	}

	/// Whether every address sits inside the declared domains.
	///
	/// No declared domain means no domain restriction. Otherwise every
	/// address must be inside the set, and an empty address set is refused:
	/// there is nothing to place it in a tenant, and failing closed is the
	/// only safe reading of "no evidence".
	fn admits_domains(&self, addresses: &[String]) -> bool {
		let Some(domains) = &self.domains else {
			return true;
		};
		if addresses.is_empty() {
			return false;
		}
		addresses.iter().all(|address| {
			address.rsplit_once('@').is_some_and(|(_, domain)| {
				let lower = domain.to_ascii_lowercase();
				domains.iter().any(|declared| declared == &lower)
			})
		})
	}

	/// The list of every account the credential may reach, given the full
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

#[cfg(test)]
mod tests;
