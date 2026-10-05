//! The ban-aware half of [`Directory`]: attaching the shared ban store and
//! the authentication entry point that consults it before hashing. Kept in
//! its own file so `directory.rs` stays readable; it is a child module so the
//! private helpers of the directory remain reachable.

use super::*;

impl Directory {
	/// Attach the shared ban store consulted on every password
	/// authentication attempt. `None` (the default) keeps the per-connection
	/// three-strikes counters as the only defence; with `[database]`
	/// configured the `serve` builder wires in a [`PgBanStore`].
	///
	/// [`PgBanStore`]: crate::antispam::bans::PgBanStore
	pub fn with_ban_store(
		mut self,
		store: std::sync::Arc<dyn crate::antispam::bans::BanStore>,
	) -> Self {
		self.ban_store = Some(store);
		self
	}

	/// The ban store attached to this directory, if any. Public so the
	/// listener tests can substitute a fake.
	pub fn ban_store(&self) -> Option<&std::sync::Arc<dyn crate::antispam::bans::BanStore>> {
		self.ban_store.as_ref()
	}

	/// Verify a login, falling back to the account's app passwords when the
	/// primary password fails. `ip` is the client address used to enforce an app
	/// password's CIDR allowlist (an allowlisted app password is unusable
	/// without it). `protocol` tags the authentication path (SMTP submission,
	/// IMAP, POP3, ManageSieve, the API, OAuth approval, or WebDAV) so an
	/// account with a per-account `allowed_protocols` set can sign in only
	/// through a protocol it actually opts into; every other path returns
	/// `None` here, mirroring the wire-level no-oracle for an unknown account.
	///
	/// Fail-closed and no user-enumeration oracle: an unknown login returns
	/// `None` from [`Directory::credentials`] before any hashing, exactly as a
	/// known account whose primary and every app password mismatch; both end in
	/// `None`. The app-password fallback runs only for a resolved account, so it
	/// does not change the unknown-vs-known timing class. The protocol
	/// allowlist runs on the resolved account name, so a "wrong protocol" and
	/// a "wrong password" share the same wire outcome.
	///
	/// LDAP is consulted last and only when the local credential path yields no
	/// match: local and SQL accounts authenticate without an LDAP round trip, and
	/// an LDAP-only login (no local entry) still gets a live bind. The LDAP path
	/// fails closed to `None` (unknown user and bad password are indistinguishable).
	///
	/// The structured audit event is emitted on the way out, with the
	/// resolved account (or `unknown` for a failure) and the login the client
	/// presented; never the plaintext password nor the TOTP code.
	pub fn authenticate_with_ip(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) -> Option<String> {
		// Ban check first: an active ban on the client IP or on the
		// account is the answer, so the password verifier is never reached.
		// The check runs before the credentials lookup so a banned IP
		// cannot probe unknown logins either. The wire response is the
		// generic "authentication failed" (no oracle), and the audit log
		// records the rule that fired.
		let outcome = self.check_bans_then_authenticate(login, password, ip, protocol);
		self.record_auth_outcome(login, outcome.as_deref(), ip, protocol);
		self.record_ban_outcome(login, outcome.as_deref(), ip, protocol);
		outcome
	}

	/// The shared ban-aware authentication path used by every listener.
	/// Refuses banned subjects before any hashing; otherwise runs the
	/// local/LDAP/allowlist chain; then updates the ban store on the
	/// outcome (record on failure, clear on success).
	fn check_bans_then_authenticate(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) -> Option<String> {
		if let Some(store) = self.ban_store.as_ref() {
			let now_secs = unix_now_secs();
			if let Some(ip) = ip
				&& let Some(info) = block_on_async(
					store.is_banned(&crate::antispam::bans::subject_ip(ip), now_secs),
				) {
				self.log_banned(
					"ip",
					&ip.to_string(),
					&info.reason,
					info.until_secs,
					protocol,
				);
				return None;
			}
			// Resolve the account name before consulting its ban row so
			// unknown logins cannot probe bans on accounts they cannot
			// authenticate as.
			if let Some((account, _)) = self.credentials(login)
				&& let Some(info) = block_on_async(
					store.is_banned(&crate::antispam::bans::subject_account(&account), now_secs),
				) {
				self.log_banned("account", &account, &info.reason, info.until_secs, protocol);
				return None;
			}
		}
		self.authenticate_local(login, password, ip)
			.or_else(|| {
				// Local/SQL credentials did not match: try the live LDAP bind, if any.
				self.ldap
					.as_ref()
					.and_then(|ldap| ldap.authenticate(login, password))
			})
			.and_then(|account| {
				// The protocol allowlist is enforced after the local/LDAP
				// credential check resolves an account. A restriction that
				// denies this protocol returns None exactly like the disabled
				// path, so the wire response is identical for "wrong password",
				// "disabled", and "wrong protocol"; none reveals that the
				// account exists at all.
				self.is_protocol_allowed(&account, protocol)
					.then_some(account)
			})
	}

	/// Emit a structured audit event when a ban fires. Distinct from
	/// `record_auth_outcome`: the latter is the per-attempt login outcome
	/// (succeeded/failed), while this one names the rule that fired so an
	/// operator can correlate one log line with the same line in the ban
	/// table.
	fn log_banned(
		&self,
		kind: &str,
		identifier: &str,
		reason: &str,
		until_secs: u64,
		protocol: crate::config::Protocol,
	) {
		tracing::info!(
			target: "epistle::auth",
			event = "auth.banned",
			kind = %kind,
			identifier = %identifier,
			reason = %reason,
			until_secs = %until_secs,
			protocol = protocol.as_str(),
			"authentication refused by ban"
		);
	}

	/// After the authentication outcome is known, write it back to the
	/// shared ban store. A failure records against both the IP (when
	/// known) and the resolved account; a success clears both. No ban
	/// store means no-op, which keeps the listener test path identical
	/// to the pre-ban-store behaviour.
	fn record_ban_outcome(
		&self,
		login: &str,
		outcome: Option<&str>,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) {
		let Some(store) = self.ban_store.as_ref() else {
			return;
		};
		let now_secs = unix_now_secs();
		let protocol_str = protocol.as_str();
		match outcome {
			Some(account) => {
				if let Some(ip) = ip {
					block_on_async(store.clear_success(&crate::antispam::bans::subject_ip(ip)));
				}
				block_on_async(
					store.clear_success(&crate::antispam::bans::subject_account(account)),
				);
			}
			None => {
				if let Some(ip) = ip {
					block_on_async(store.record_failure(
						&crate::antispam::bans::subject_ip(ip),
						protocol_str,
						now_secs,
					));
				}
				if let Some((account, _)) = self.credentials(login) {
					block_on_async(store.record_failure(
						&crate::antispam::bans::subject_account(&account),
						protocol_str,
						now_secs,
					));
				}
			}
		}
	}
}
