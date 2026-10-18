//! Bearer checks on [`ApiState`]: whether a bearer is the configured static
//! token, whether an API key admits it for a scope, and the reach that
//! follows.
//!
//! The configured token's hash may be a legacy argon2id one, so comparing a
//! bearer against it is expensive. The bearer middleware does that once per
//! request and records the answer in [`MatchedAuth::configured`]; everything
//! after it (the account-bound gate, the principal, the per-call scope
//! checks) reads that answer and only walks the API keys, whose hashes are
//! SHA-256.

use super::{ApiState, MatchedAuth};
use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::domain_scope::DomainScope;
use crate::api::error::ApiError;

impl ApiState {
	/// The domains the credentials in `auth` are allowed to act on.
	///
	/// The static token is unrestricted. A key carries whatever it declared,
	/// and a key that declared nothing keeps the reach every key had before
	/// the field existed. Credentials that match no key at all admit no
	/// domain: the middleware has already authorized the request by the time
	/// a handler asks, so failing to identify the key here means the state
	/// changed underneath us, and that is not a reason to widen anyone.
	pub fn domain_scope(&self, auth: &MatchedAuth) -> DomainScope {
		let Some(token) = auth.token.as_deref() else {
			return DomainScope::Only(Vec::new());
		};
		if auth.configured {
			return DomainScope::All;
		}
		const EVERY_SCOPE: &[Scope] = &[Scope::Read, Scope::Write, Scope::Send, Scope::Scim];
		self.inner
			.api_keys
			.snapshot()
			.iter()
			.find(|key| key.admits_any(token, auth.client_ip, now(), EVERY_SCOPE))
			.map_or_else(|| DomainScope::Only(Vec::new()), DomainScope::of_key)
	}

	/// Whether any non-expired, IP-permitted API key's hash matches `token`
	/// from `client_ip` and carries at least one of `acceptable_scopes`.
	/// Fail-closed: an expired, IP-restricted or under-scoped key that does
	/// not match is no different from no key at all. The configured token is
	/// not considered here; see [`Self::bearer_is_configured`].
	///
	/// Pass a single-element slice when the route is unambiguous (e.g.
	/// `POST /api/v1/send` is always `Send`); pass a multi-element slice
	/// when the coarse path/method inference is ambiguous and the handler
	/// will tighten (e.g. `POST /jmap/api`, where the actual scope depends on
	/// the JMAP method in the request body).
	pub(super) fn key_authorizes(
		&self,
		token: &str,
		client_ip: Option<std::net::IpAddr>,
		acceptable_scopes: &[Scope],
	) -> bool {
		let keys = self.inner.api_keys.snapshot();
		let matched = keys
			.iter()
			.find(|key| key.admits_any(token, client_ip, now(), acceptable_scopes));
		if let Some(key) = matched
			&& key.scopes.is_empty()
		{
			self.warn_legacy_key_once(&key.label);
		}
		matched.is_some()
	}

	/// Emit the one-time-per-key warning for legacy (un-scoped) keys. The
	/// state is shared across requests (it lives behind an `Arc`), so the
	/// `Mutex<HashSet>` deduplicates: an operator who restarts will see one
	/// warning per legacy key per process lifetime, not one per request.
	fn warn_legacy_key_once(&self, label: &str) {
		let mut warned = self
			.inner
			.legacy_warned
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if warned.insert(label.to_string()) {
			tracing::warn!(
				key_label = label,
				"API key has no scopes; granting full legacy access. \
				 Scopes will be required in a future release; rotate this key \
				 with `--scope read|write|send` to keep its blast radius small."
			);
		}
	}

	/// Re-check `principal` against `scope`. Used by handlers whose scope
	/// cannot be inferred from path+method (most JMAP method calls: the same
	/// `POST /jmap/api` route serves reads, writes and outbound submissions
	/// depending on the request body, so the middleware's coarse inference
	/// defaults to passing any scoped key and lets each handler tighten it).
	/// The middleware never calls this; the path/method inference it does is
	/// enough for the routes that reach it.
	///
	/// When the principal carries a credential (`Account` or `Domains` or a
	/// key-shaped `Admin`), scope is decided by the API key that
	/// authenticated, from the same peer. A principal carries a credential
	/// only when its bearer was not the configured token, so the configured
	/// hash is not compared again. The bare `Admin` (the configured static
	/// token) admits every scope; any other principal without a credential
	/// admits none.
	pub fn require_scope_for_principal(
		&self,
		principal: &Principal,
		scope: Scope,
	) -> Result<(), ApiError> {
		let allowed = match principal.credential() {
			Some(credential) => {
				self.key_authorizes(&credential.token, credential.client_ip, &[scope])
			}
			None => matches!(principal, Principal::Admin { .. }),
		};
		if allowed {
			Ok(())
		} else {
			Err(ApiError::unauthenticated())
		}
	}

	/// Whether `token` from `client_ip` passes the middleware for a route
	/// that needs one of `acceptable_scopes`: the configured token, or a key
	/// [`Self::key_authorizes`] admits.
	#[cfg(test)]
	pub(super) fn authorizes(
		&self,
		token: &str,
		client_ip: Option<std::net::IpAddr>,
		acceptable_scopes: &[Scope],
	) -> bool {
		self.bearer_is_configured(token) || self.key_authorizes(token, client_ip, acceptable_scopes)
	}

	/// Whether `token` is the configured static token. Called once per
	/// request, by the bearer middleware; see the module documentation.
	pub(super) fn bearer_is_configured(&self, token: &str) -> bool {
		#[cfg(test)]
		super::CONFIGURED_HASH_CHECKS.with(|checks| checks.set(checks.get() + 1));
		let stored = &self.inner.token_hash;
		if let Some(expected_hex) = stored.strip_prefix("sha256:") {
			// O(1) SHA-256: correct threat model for a bearer token.
			// Comparing hex-encoded digests: timing leaks here cannot reveal
			// the preimage (SHA-256 is pre-image resistant).
			let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
			let actual_hex = digest
				.as_ref()
				.iter()
				.fold(String::with_capacity(64), |mut s, b| {
					use std::fmt::Write;
					write!(s, "{b:02x}").ok();
					s
				});
			crate::util::constant_time::eq(expected_hex.as_bytes(), actual_hex.as_bytes())
		} else {
			self.verify_legacy_configured(token)
		}
	}
}

impl ApiState {
	/// The legacy path of [`Self::bearer_is_configured`]: an argon2id hash.
	///
	/// Once the real token has verified, its SHA-256 is kept and a bearer is
	/// compared by digest, so a wrong one costs nothing. Until then every
	/// wrong token costs an argon2 and anyone can send them, so those checks
	/// draw on one budget for the whole server; when it is spent the bearer
	/// counts as not configured without hashing. The only price is that the
	/// very first use of the configured token, during a flood of wrong ones,
	/// fails until the window rolls.
	fn verify_legacy_configured(&self, token: &str) -> bool {
		let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
		if let Some(known) = self.inner.configured_digest.get() {
			return crate::util::constant_time::eq(known, digest.as_ref());
		}
		let now = std::time::Instant::now();
		let allowed = self
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.slow_check_allowed(now);
		if !allowed {
			return false;
		}
		#[cfg(test)]
		super::CONFIGURED_ARGON2_RUNS.with(|runs| runs.set(runs.get() + 1));
		if crate::smtp::auth::verify_password(&self.inner.token_hash, token) {
			let mut known = [0u8; 32];
			known.copy_from_slice(digest.as_ref());
			let _ = self.inner.configured_digest.set(known);
			true
		} else {
			self.inner
				.auth_limiter
				.lock()
				.unwrap_or_else(|p| p.into_inner())
				.slow_check_failed(now);
			false
		}
	}
}

/// Seconds since the epoch, for key expiry.
fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}
