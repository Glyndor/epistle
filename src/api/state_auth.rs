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
	/// not considered here; see [`Self::bearer_is_configured_async`].
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

	/// Whether `token` is the configured static token, synchronously. Tests
	/// use it; the bearer middleware uses [`Self::bearer_is_configured_async`].
	#[cfg(test)]
	pub(super) fn bearer_is_configured(&self, token: &str) -> bool {
		super::CONFIGURED_HASH_CHECKS.with(|checks| checks.set(checks.get() + 1));
		if self.inner.token_hash.starts_with("sha256:") {
			self.configured_by_digest(token)
		} else {
			crate::smtp::auth::verify_password(&self.inner.token_hash, token)
		}
	}
}

/// Too many wrong-looking tokens are already waiting for an argon2.
#[derive(Debug)]
pub(super) struct ArgonBusy;

impl ApiState {
	/// [`Self::bearer_is_configured`] for the middleware: the same answer, but
	/// a legacy argon2id hash is verified off the async workers
	/// and at most [`super::MAX_CONCURRENT_ARGON2`] at a time.
	///
	/// Why a gate and not a budget: the operator's real token must never be
	/// refused because of what others sent, and a budget anyone can fill does
	/// exactly that. A gate bounds the CPU a flood of wrong tokens can take
	/// (two cores' worth, the rest of the requests wait their turn) and
	/// refuses nobody. Once the real token has verified, its SHA-256 is kept
	/// and a wrong bearer costs a digest comparison, with no argon2 at all.
	pub(super) async fn bearer_is_configured_async(
		&self,
		token: &str,
		client_ip: Option<std::net::IpAddr>,
	) -> Result<bool, ArgonBusy> {
		#[cfg(test)]
		super::CONFIGURED_HASH_CHECKS.with(|checks| checks.set(checks.get() + 1));
		if self.inner.token_hash.starts_with("sha256:") {
			return Ok(self.configured_by_digest(token));
		}
		let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
		if let Some(known) = self.inner.configured_digest.get() {
			return Ok(crate::util::constant_time::eq(known, digest.as_ref()));
		}
		let mut known = [0u8; 32];
		known.copy_from_slice(digest.as_ref());
		// A bounded queue: a flood waits at most this long, and the request
		// that would be one too many is refused instead of piling up.
		let _waiting = super::state_auth_queue::Waiting::enter(
			&self.inner.argon2_waiting,
			client_ip,
			self.inner.argon2_queue_max,
		)
		.ok_or(ArgonBusy)?;
		let Ok(permit) = std::sync::Arc::clone(&self.inner.argon2_gate)
			.acquire_owned()
			.await
		else {
			return Ok(false);
		};
		// Someone ahead of us in the queue may have just learned the token.
		if let Some(real) = self.inner.configured_digest.get() {
			return Ok(crate::util::constant_time::eq(real, &known));
		}
		let (state, bearer) = (self.clone(), token.to_string());
		// The permit travels into the blocking task: it is released when the
		// argon2 ends, not when this request is dropped, so a client that
		// hangs up cannot start the next verification while one still runs.
		let verified = tokio::task::spawn_blocking(move || {
			let _permit = permit;
			#[cfg(test)]
			state.argon2_run_started();
			let verified = crate::smtp::auth::verify_password(&state.inner.token_hash, &bearer);
			#[cfg(test)]
			state.argon2_run_ended();
			if verified {
				let _ = state.inner.configured_digest.set(known);
			}
			verified
		})
		.await
		.unwrap_or(false);
		Ok(verified)
	}

	/// The `sha256:` hash form: one digest comparison.
	fn configured_by_digest(&self, token: &str) -> bool {
		let Some(expected_hex) = self.inner.token_hash.strip_prefix("sha256:") else {
			return false;
		};
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
	}

	#[cfg(test)]
	fn argon2_run_started(&self) {
		use std::sync::atomic::Ordering::SeqCst;
		let stats = &self.inner.argon2_stats;
		stats[0].fetch_add(1, SeqCst);
		let now = stats[1].fetch_add(1, SeqCst) + 1;
		stats[2].fetch_max(now, SeqCst);
	}

	#[cfg(test)]
	fn argon2_run_ended(&self) {
		self.inner.argon2_stats[1].fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
	}
}

/// Seconds since the epoch, for key expiry.
fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}
