//! Builder methods that fill a [`Directory`] from the configuration.

use super::{AliasSpec, Directory};
use crate::password::Policy;
use crate::util::address::normalize;

impl Directory {
	/// Attach a live LDAP/AD authenticator, consulted by
	/// [`Directory::authenticate_with_ip`] only after the local credential path
	/// fails. Shared behind an `Arc` so directory rebuilds keep one worker thread.
	pub fn with_ldap(
		mut self,
		ldap: Option<std::sync::Arc<crate::directory_store::LdapAuthenticator>>,
	) -> Self {
		self.ldap = ldap;
		self
	}

	/// Attach the shared metrics handle so every password-based
	/// authentication attempt bumps `auth_login_succeeded` /
	/// `auth_login_failed`. The structured tracing event is always emitted
	/// regardless — the counter is a derived view, the audit log is the
	/// primary record. Unset in unit tests that do not exercise counters.
	pub fn with_metrics(mut self, metrics: std::sync::Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Set the runtime password policy. Verification through
	/// [`Directory::authenticate`] normalises the candidate the same way
	/// the storage layer did at set-time, so a non-ASCII password typed
	/// in one decomposition verifies the same as its NFKC canonical form.
	pub fn with_password_policy(mut self, policy: Policy) -> Self {
		self.password_policy = policy;
		self
	}

	/// Attach per-account app passwords (account name → list). Account keys are
	/// lowercased to match the authentication lookup.
	pub fn with_app_passwords(
		mut self,
		entries: impl IntoIterator<Item = (String, crate::directory_store::AppPassword)>,
	) -> Self {
		for (account, password) in entries {
			self.app_passwords
				.entry(account.to_ascii_lowercase())
				.or_default()
				.push(password);
		}
		self.max_app_passwords = self.app_passwords.values().map(Vec::len).max().unwrap_or(0);
		self
	}

	/// Attach enabled masked email addresses (lowercased address → owning
	/// account). Disabled masks are never inserted here — `resolve` and
	/// `owns_address` must treat them identically to an unknown user so a
	/// disabled mask never reveals that one once existed.
	pub fn with_masked(mut self, entries: impl IntoIterator<Item = (String, String)>) -> Self {
		self.masked_by_address = entries
			.into_iter()
			.map(|(address, account)| (normalize(&address), account))
			.collect();
		self
	}

	/// Attach the masked addresses that are switched off, so a delivery that
	/// finds one can tell it from an address nobody had.
	pub fn with_masked_paused(mut self, entries: impl IntoIterator<Item = String>) -> Self {
		self.masked_paused = entries
			.into_iter()
			.map(|address| normalize(&address))
			.collect();
		self
	}

	/// Attach multi-target aliases (alias address → spec).
	pub fn with_aliases(mut self, aliases: impl IntoIterator<Item = (String, AliasSpec)>) -> Self {
		self.aliases = aliases
			.into_iter()
			.map(|(address, spec)| (normalize(&address), spec))
			.collect();
		self
	}

	/// Attach TOTP secrets (account name → base32 secret) for two-factor auth.
	pub fn with_totp(mut self, totp: impl IntoIterator<Item = (String, String)>) -> Self {
		self.totp = totp
			.into_iter()
			.map(|(name, secret)| (name.to_ascii_lowercase(), secret))
			.collect();
		self
	}

	/// Attach per-account forwarding: account name → (target addresses,
	/// keep_local).
	pub fn with_forwards(
		mut self,
		forwards: impl IntoIterator<Item = (String, (Vec<String>, bool))>,
	) -> Self {
		self.forwards = forwards
			.into_iter()
			.map(|(name, spec)| (name.to_ascii_lowercase(), spec))
			.collect();
		self
	}

	/// Attach domain aliases (alias domain → target domain). Both sides are
	/// lowercased to match resolution.
	pub fn with_domain_aliases(
		mut self,
		aliases: impl IntoIterator<Item = (String, String)>,
	) -> Self {
		self.domain_aliases = aliases
			.into_iter()
			.map(|(alias, target)| (alias.to_ascii_lowercase(), target.to_ascii_lowercase()))
			.collect();
		self
	}

	/// Attach per-domain catch-all accounts (domain → account name). Domains
	/// are lowercased to match resolution.
	pub fn with_catch_all(mut self, catch_all: impl IntoIterator<Item = (String, String)>) -> Self {
		self.catch_all = catch_all
			.into_iter()
			.map(|(domain, account)| (domain.to_ascii_lowercase(), account))
			.collect();
		self
	}

	/// Override the sub-address separators (default `['+']`). An empty list
	/// disables sub-addressing entirely.
	pub fn with_subaddress_separators(
		mut self,
		separators: impl IntoIterator<Item = char>,
	) -> Self {
		self.subaddress_separators = separators.into_iter().collect();
		self
	}

	/// Attach password hashes (account name → argon2id PHC string).
	pub fn with_password_hashes(
		mut self,
		hashes: impl IntoIterator<Item = (String, String)>,
	) -> Self {
		self.password_hashes = hashes.into_iter().collect();
		self
	}
}
