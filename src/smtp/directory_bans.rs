//! The ban-aware half of [`Directory`]: attaching the shared ban store and
//! the authentication entry points that consult it before hashing. Kept in
//! its own file so `directory.rs` stays readable; it is a child module so the
//! private helpers of the directory remain reachable.
//!
//! Two shared operations live here and are used by every password-based
//! authentication path (PLAIN/LOGIN today, SCRAM-SHA-256 the moment it
//! calls into the directory):
//!
//! - [`Directory::check_ban`] is the "consult the ban store before any
//!   credential lookup" half. It checks the IP first (no lookup), then the
//!   account (a single `credentials` lookup). A ban refusal returns
//!   [`BanOutcome::Banned`] and the caller must NOT add a strike.
//! - [`Directory::record_ban_outcome`] is the "write the outcome back"
//!   half. A success clears both subjects, a credential failure records a
//!   strike against both.
//!
//! Together they form the shared authentication gate: PLAIN/LOGIN wraps
//! them around `authenticate_local`, SCRAM wraps them around the SCRAM
//! proof, and both key the ban store the same way (`ip:<peer>` and
//! `account:<login>`).

use super::*;
use crate::antispam::bans;

/// The result of consulting the ban store before any credential work.
/// A ban refusal is a distinct outcome from a credential failure and must
/// not add a strike; the caller returns the wire failure (no oracle) and
/// does not call `record_ban_outcome`.
#[derive(Debug)]
pub enum BanOutcome {
	/// The subject is not banned. `account` is the resolved account name
	/// when the login resolved locally, `None` for an unknown login.
	Clear {
		/// The account the ban check resolved, or `None` if the login is
		/// unknown locally. The caller uses this to key the account side
		/// of the outcome recording.
		account: Option<String>,
	},
	/// The subject is banned. The audit event has already been emitted
	/// (see `log_banned`); the caller returns the wire failure and does
	/// not call `record_ban_outcome`.
	Banned,
}

impl Directory {
	/// The stand-in account name an unknown login is counted under so it does
	/// the ban store work a real one does: `?` (not a character an account
	/// name can hold) and a keyed hash of the login. Each unknown login has
	/// counters and bans of its own, like a real account, so neither a pile
	/// of unknown logins sharing one row nor a ban on one of them is visible
	/// from another. The key lives only in this process.
	pub(crate) fn decoy_account(login: &str) -> String {
		use ring::hmac;
		static KEY: std::sync::OnceLock<hmac::Key> = std::sync::OnceLock::new();
		let key = KEY.get_or_init(|| {
			let bytes: [u8; 32] = ring::rand::generate(&ring::rand::SystemRandom::new())
				.map(|random| random.expose())
				.unwrap_or([0u8; 32]);
			hmac::Key::new(hmac::HMAC_SHA256, &bytes)
		});
		let tag = hmac::sign(key, login.to_ascii_lowercase().as_bytes());
		tag.as_ref()[..12]
			.iter()
			.fold(String::from("?"), |mut s, b| {
				use std::fmt::Write;
				let _ = write!(s, "{b:02x}");
				s
			})
	}

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
		self.authenticate_with_ip_full(login, password, ip, protocol)
			.map(|(account, _label)| account)
	}

	/// Like [`Directory::authenticate_with_ip`], but also returns the
	/// label of the app password that authenticated. Callers that need
	/// per-credential overrides (`save_sent`, ...) use the label to look
	/// them up; primary-password logins return `None` so the caller
	/// falls through to the account-wide default. LDAP-bind logins also
	/// return `None` (LDAP does not surface the credential that matched,
	/// so the per-credential override cannot apply).
	pub fn authenticate_with_ip_full(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) -> Option<(String, Option<String>)> {
		match self.authenticate_verdict(login, password, ip, protocol) {
			hash_gate::Verdict::Admitted { account, label } => Some((account, label)),
			hash_gate::Verdict::Refused | hash_gate::Verdict::Busy => None,
		}
	}

	/// Like [`Directory::authenticate_with_ip_full`], but tells a refusal from
	/// a sign-in turned away because the password-check gate was full. Only
	/// the sessions that can answer with a temporary failure call it.
	pub fn authenticate_verdict(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) -> hash_gate::Verdict {
		// Ban check first: an active ban on the client IP or on the
		// account is the answer, so the password verifier is never reached.
		// The check runs before the credentials lookup so a banned IP
		// cannot probe unknown logins either. The wire response is the
		// generic "authentication failed" (no oracle), and the audit log
		// records the rule that fired. A ban refusal is distinct from a
		// credential failure: the strike count and ban expiry do not
		// move, so the ban keeps ending when it was going to end.
		let resolved_account = match self.check_ban(login, ip, protocol) {
			BanOutcome::Banned => {
				self.record_auth_outcome(login, None, ip, protocol);
				return hash_gate::Verdict::Refused;
			}
			BanOutcome::Clear { account } => account,
		};
		// The hashing runs off the async worker and a few at a time. A check
		// turned away for lack of a place verified nothing: it moves no
		// strike, it is not a failed login, and the session says "try again".
		let Ok(local) = self
			.hash_gate
			.run(|| self.authenticate_local(login, password, ip, protocol))
		else {
			self.note_gate_rejection(protocol);
			return hash_gate::Verdict::Busy;
		};
		let verified = local
			.or_else(|| {
				// Local/SQL credentials did not match: try the live LDAP bind, if any.
				self.ldap
					.as_ref()
					.and_then(|ldap| ldap.authenticate(login, password))
					.map(|account| (account, None))
			})
			.and_then(|(account, label)| {
				// The account rules run after the local/LDAP credential
				// check resolves an account, on whichever one answered: an
				// account the rules refuse returns None exactly like a wrong
				// password, so the wire response says nothing about why.
				self.admit_login(&account, protocol, Proof::Password)
					.then_some((account, label))
			});
		let verified_account = verified.as_ref().map(|(account, _)| account.as_str());
		self.record_auth_outcome(login, verified_account, ip, protocol);
		// Key the account-side strike on the account the credential check
		// resolved; fall back to whatever the ban check saw when the
		// password check rejected a known login (e.g. wrong password, an
		// app-password CIDR miss, a protocol allowlist denial). An unknown
		// login never reaches the account side.
		let account_for_record = verified_account.or(resolved_account.as_deref());
		self.record_ban_outcome(login, account_for_record, verified.is_some(), ip, protocol);
		match verified {
			Some((account, label)) => hash_gate::Verdict::Admitted { account, label },
			None => hash_gate::Verdict::Refused,
		}
	}

	/// The shared ban check that every password-based authentication path
	/// runs before any credential lookup. PLAIN/LOGIN call it via
	/// [`Directory::authenticate_with_ip`]; SCRAM calls it directly in the
	/// client-first handler so the SCRAM credential lookup never happens
	/// for a banned subject.
	///
	/// The IP check runs first and needs no lookup; the account check
	/// resolves the login once and consults the account ban row. A
	/// ban refusal returns [`BanOutcome::Banned`] and the audit event
	/// (`auth.banned`) has already been emitted; the caller must not call
	/// `record_ban_outcome` for it.
	pub fn check_ban(
		&self,
		login: &str,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) -> BanOutcome {
		let Some(store) = self.ban_store.as_ref() else {
			return BanOutcome::Clear {
				account: self.credentials(login).map(|(account, _)| account),
			};
		};
		let now_secs = unix_now_secs();
		if let Some(ip) = ip {
			// The exact address is always asked about: that is where an
			// operator's manual ban or allow entry for one host lives. For
			// IPv6 the /64 the failures are counted under is asked about too,
			// unless the host itself is on the allow list: a neighbour in its
			// /64 that earned a ban must not lock it out.
			let mut subjects = vec![bans::subject_ip(ip)];
			if ip.is_ipv6() && !block_on_async(store.is_allow_listed(ip)) {
				subjects.push(bans::subject_client(ip));
			}
			for subject in subjects {
				if let Some(info) = block_on_async(store.is_banned(&subject, now_secs)) {
					self.log_banned(
						"ip",
						&ip.to_string(),
						&info.reason,
						info.until_secs,
						protocol,
					);
					return BanOutcome::Banned;
				}
			}
		}
		// Resolve the account name before consulting its ban rows so
		// unknown logins cannot probe bans on accounts they cannot
		// authenticate as.
		let account = self.credentials(login).map(|(account, _)| account);
		// An unknown login asks the store about a stand-in account all the
		// same, and ignores the answer: with PostgreSQL each question is a round
		// trip, and one asked only for real accounts would tell them apart.
		let decoy;
		let subject_account = match account.as_deref() {
			Some(account) => account,
			// No login at all (a malformed first message) has nothing to hide.
			None if login.is_empty() => return BanOutcome::Clear { account },
			None => {
				decoy = Self::decoy_account(login);
				&decoy
			}
		};
		let subjects = [
			("pair", bans::subject_pair(subject_account, ip)),
			("account", bans::subject_account(subject_account)),
		];
		for (kind, subject) in subjects {
			if let Some(info) = block_on_async(store.is_banned(&subject, now_secs))
				&& let Some(account) = &account
			{
				self.log_banned(kind, account, &info.reason, info.until_secs, protocol);
				return BanOutcome::Banned;
			}
		}
		BanOutcome::Clear { account }
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
	/// shared ban store. A credential failure records against both the IP
	/// (when known) and the resolved account; a success clears both. A
	/// ban refusal is NOT recorded here (the caller never reaches this
	/// method for a ban refusal), so the strike count and the ban
	/// expiry stay where they were.
	///
	/// `account` is the account the ban check or the credential check
	/// resolved; `None` when the login did not resolve locally, so the
	/// account-side strike is skipped and only the IP-side strike lands.
	pub fn record_ban_outcome(
		&self,
		login: &str,
		account: Option<&str>,
		success: bool,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) {
		let Some(store) = self.ban_store.as_ref() else {
			return;
		};
		let now_secs = unix_now_secs();
		let protocol_str = protocol.as_str();
		if success {
			// A success clears what the account and this account-from-this-
			// client pair had accumulated. It never clears the client: a
			// client that owns one account must not be able to reset its
			// own count between guesses at others.
			if let Some(account) = account {
				block_on_async(store.clear_success(&bans::subject_pair(account, ip)));
				block_on_async(store.clear_success(&bans::subject_account(account)));
			}
			return;
		}
		// An allow-listed client is exempt from the bans on its address and on
		// the pair too: it may be a proxy that many users share, and five typos
		// from them must not lock one account's owner out of the proxy. What it
		// is not exempt from is the account's own ceiling (four times the
		// threshold), or a trusted network could guess without limit.
		let allowed = ip.is_some_and(|ip| block_on_async(store.is_allow_listed(ip)));
		if let Some(ip) = ip
			&& !allowed
		{
			block_on_async(store.record_failure(&bans::subject_client(ip), protocol_str, now_secs));
		}
		// An unknown login is counted on a stand-in account (never read back),
		// so it writes what a real one does; see `check_ban`.
		let decoy;
		let account = match account {
			Some(account) => account,
			None if login.is_empty() => return,
			None => {
				decoy = Self::decoy_account(login);
				&decoy
			}
		};
		if !allowed {
			block_on_async(store.record_failure(
				&bans::subject_pair(account, ip),
				protocol_str,
				now_secs,
			));
		}
		// Every failure also counts against the account, at a threshold several
		// times the client's (see `ACCOUNT_THRESHOLD_FACTOR`): a guess spread
		// over many clients, none enough to be banned, still ends in a ban,
		// and one client alone is stopped by its own counters long before.
		block_on_async(store.record_failure(
			&bans::subject_account(account),
			protocol_str,
			now_secs,
		));
	}
}
