//! Recipient resolution: which account, if any, receives an address.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use super::address::Address;

/// Run an async future synchronously from a non-async context. Every
/// listener's authentication path is synchronous (the sans-IO state
/// machines drive the I/O layer), so the ban store's async methods must
/// be drained through this helper. The calls are short single-query
/// reads and writes; the production runtime is multi-threaded, so the
/// `block_in_place` worker park keeps sibling tasks on the same runtime
/// running while the ban store completes. A current-thread runtime would
/// deadlock on the helper, so the unit tests must declare
/// `#[tokio::test(flavor = "multi_thread")]`; a panic surfaces the
/// mistake at the call site.
fn block_on_async<F: Future>(future: F) -> F::Output {
	let handle = tokio::runtime::Handle::current();
	match handle.runtime_flavor() {
		tokio::runtime::RuntimeFlavor::MultiThread => {
			tokio::task::block_in_place(move || handle.block_on(future))
		}
		tokio::runtime::RuntimeFlavor::CurrentThread => panic!(
			"Directory::authenticate_with_ip cannot block a current-thread \
			 tokio runtime; switch the test to #[tokio::test(flavor = \"multi_thread\")] \
			 or remove the ban store"
		),
		_ => handle.block_on(future),
	}
}

/// Current Unix timestamp in seconds, with the same fall-back the rest of
/// the auth path uses for an impossible pre-epoch clock.
fn unix_now_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Outcome of resolving a recipient address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
	/// The domain is not served here; accepting would mean relaying.
	NotLocal,
	/// The domain is local but no account owns the address.
	UnknownUser,
	/// The address belongs to this account.
	Account(String),
	/// The address is a multi-target alias delivering to these accounts.
	Alias(Vec<String>),
}

/// A multi-target alias: the member accounts' addresses, who may send as it,
/// and whether its membership is disclosed.
#[derive(Debug, Clone)]
pub struct AliasSpec {
	/// Member addresses (each a local account address).
	pub members: Vec<String>,
	/// Addresses permitted to send as the alias; empty means any member.
	pub senders: Vec<String>,
	/// Keep the membership private (not disclosed via [`Directory::alias_members`]).
	pub hidden: bool,
	/// When set, this alias is a mailing list with the given `List-Id`; delivered
	/// copies gain `List-Id`/`List-Post`/`List-Unsubscribe` headers.
	pub list_id: Option<String>,
}

/// Immutable lookup table built from the configuration.
#[derive(Debug, Default)]
pub struct Directory {
	domains: HashSet<String>,
	accounts_by_address: HashMap<String, String>,
	/// argon2id PHC hash per account name. Accounts without one cannot
	/// authenticate (receive-only).
	password_hashes: HashMap<String, String>,
	/// Sub-address separators (RFC 5233 detail): `user+tag@domain` is
	/// delivered to `user@domain`. Empty disables sub-addressing.
	subaddress_separators: Vec<char>,
	/// Per-domain catch-all account: mail for an otherwise-unknown local user
	/// in this domain is delivered here. Absent means unknown users are
	/// rejected (the secure default).
	catch_all: HashMap<String, String>,
	/// Domain aliases (alias domain → target domain): mail to `user@alias` is
	/// resolved as `user@target`.
	domain_aliases: HashMap<String, String>,
	/// SCRAM credentials per account name, for SCRAM-SHA-256 authentication.
	scram: HashMap<String, super::scram::ScramStored>,
	/// Base32 TOTP secret per account name, for two-factor auth (RFC 6238).
	totp: HashMap<String, String>,
	/// Account names administratively disabled (kept on disk, cannot
	/// authenticate). SCIM `active: false` lands here.
	disabled: HashSet<String>,
	/// Storage quota (bytes) per account name; absent falls back to the domain
	/// quota, then the server default.
	account_quotas: HashMap<String, u64>,
	/// Default storage quota (bytes) per domain, applied to accounts in that
	/// domain without their own quota.
	domain_quotas: HashMap<String, u64>,
	/// Per-domain submission rate limit (messages per minute) for authenticated
	/// senders in that domain. An account picks up its domain's limit when one
	/// is set; otherwise the server-wide default applies (or no limit, if
	/// neither is configured).
	domain_submission_limits: HashMap<String, u32>,
	/// Per-account external forwarding: `(targets, keep_local)`. Mail for the
	/// account is also queued to each target; `keep_local` keeps the local copy.
	forwards: HashMap<String, (Vec<String>, bool)>,
	/// Multi-target aliases, keyed by lowercased alias address.
	aliases: HashMap<String, AliasSpec>,
	/// Secondary app passwords per account name. Each entry is tried when the
	/// primary password check fails (see [`Directory::authenticate_with_ip`]).
	app_passwords: HashMap<String, Vec<crate::directory_store::AppPassword>>,
	/// Optional live LDAP/AD authenticator. Consulted only when the local
	/// credential path yields no match, so local and SQL accounts never incur an
	/// LDAP round trip (see [`Directory::authenticate_with_ip`]).
	ldap: Option<std::sync::Arc<crate::directory_store::LdapAuthenticator>>,
	/// Enabled masked email addresses (lowercased address → owning account).
	/// Disabled masks are not present here, so they reject exactly like an
	/// unknown user (the directory never reveals that one once existed).
	masked_by_address: HashMap<String, String>,
	/// Shared metrics handle for the audit counters (`auth_login_succeeded`
	/// / `auth_login_failed`). `None` in tests that do not need the
	/// counters — a `Directory::new(...)` without `with_metrics(...)` still
	/// emits the structured tracing event, the operator log is the primary
	/// record, and the counters are a derived view.
	metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
	/// Per-account protocol allowlist. Absent (the entry is missing) means
	/// every protocol authenticates the account — the pre-restriction
	/// behaviour. Present (even empty) means only the listed protocols do;
	/// the rest reject identically to an unknown login.
	allowed_protocols: HashMap<String, HashSet<crate::config::Protocol>>,
	/// Shared ban store consulted before any password hashing and updated
	/// on every authentication outcome. `None` in deployments without
	/// `[database]` — those fall back to the per-connection three-strikes
	/// counters that the listeners already maintain.
	ban_store: Option<std::sync::Arc<dyn crate::antispam::bans::BanStore>>,
}

impl Directory {
	/// Build a directory. Domains and address keys are lowercased here so
	/// lookups are case-insensitive regardless of the config's spelling.
	pub fn new(
		domains: impl IntoIterator<Item = String>,
		address_accounts: impl IntoIterator<Item = (String, String)>,
	) -> Self {
		Directory {
			domains: domains
				.into_iter()
				.map(|domain| domain.to_ascii_lowercase())
				.collect(),
			accounts_by_address: address_accounts
				.into_iter()
				.map(|(address, account)| (address.to_ascii_lowercase(), account))
				.collect(),
			password_hashes: HashMap::new(),
			// The `+` separator is the de-facto standard, enabled by default.
			subaddress_separators: vec!['+'],
			catch_all: HashMap::new(),
			domain_aliases: HashMap::new(),
			scram: HashMap::new(),
			totp: HashMap::new(),
			disabled: HashSet::new(),
			account_quotas: HashMap::new(),
			domain_quotas: HashMap::new(),
			domain_submission_limits: HashMap::new(),
			forwards: HashMap::new(),
			aliases: HashMap::new(),
			app_passwords: HashMap::new(),
			ldap: None,
			masked_by_address: HashMap::new(),
			metrics: None,
			allowed_protocols: HashMap::new(),
			ban_store: None,
		}
	}

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
		self
	}

	/// Attach enabled masked email addresses (lowercased address → owning
	/// account). Disabled masks are never inserted here — `resolve` and
	/// `owns_address` must treat them identically to an unknown user so a
	/// disabled mask never reveals that one once existed.
	pub fn with_masked(mut self, entries: impl IntoIterator<Item = (String, String)>) -> Self {
		self.masked_by_address = entries
			.into_iter()
			.map(|(address, account)| (address.to_ascii_lowercase(), account))
			.collect();
		self
	}

	/// Attach multi-target aliases (alias address → spec).
	pub fn with_aliases(mut self, aliases: impl IntoIterator<Item = (String, AliasSpec)>) -> Self {
		self.aliases = aliases
			.into_iter()
			.map(|(address, spec)| (address.to_ascii_lowercase(), spec))
			.collect();
		self
	}

	/// The member accounts of an alias address, or `None` when the address is
	/// not an alias or its membership is hidden (privacy).
	pub fn alias_members(&self, address: &str) -> Option<Vec<String>> {
		let spec = self.aliases.get(&address.to_ascii_lowercase())?;
		(!spec.hidden).then(|| spec.members.clone())
	}

	/// Mailing-list headers (`List-Id`/`List-Post`/`List-Unsubscribe`, each with
	/// a trailing CRLF) for an address, or `None` when it is not a list. Prepended
	/// to delivered copies so clients can identify and leave the list (RFC 2369).
	pub fn list_headers(&self, address: &str) -> Option<String> {
		let spec = self.aliases.get(&address.to_ascii_lowercase())?;
		let list_id = spec.list_id.as_ref()?;
		Some(format!(
			"List-Id: <{list_id}>\r\nList-Post: <mailto:{address}>\r\n\
			 List-Unsubscribe: <mailto:{address}?subject=unsubscribe>\r\n"
		))
	}

	/// Attach TOTP secrets (account name → base32 secret) for two-factor auth.
	pub fn with_totp(mut self, totp: impl IntoIterator<Item = (String, String)>) -> Self {
		self.totp = totp
			.into_iter()
			.map(|(name, secret)| (name.to_ascii_lowercase(), secret))
			.collect();
		self
	}

	/// Mark a set of accounts as administratively disabled. While disabled,
	/// the account still owns its mailboxes and is visible to management
	/// tooling, but authentication rejects every password attempt before any
	/// hashing. Names are lowercased so the check matches `credentials()`
	/// (which also lowercases the bare-login path).
	pub fn with_disabled(mut self, names: impl IntoIterator<Item = String>) -> Self {
		self.disabled = names.into_iter().map(|n| n.to_ascii_lowercase()).collect();
		self
	}

	/// Whether `account` is administratively disabled.
	pub fn is_disabled(&self, account: &str) -> bool {
		self.disabled.contains(&account.to_ascii_lowercase())
	}

	/// Attach the per-account protocol allowlist (account name → set of
	/// protocols the account may authenticate through). Account names are
	/// lowercased to match `credentials()`. An absent entry is
	/// "every protocol authenticates" (the default for accounts that never
	/// opted into the restriction); an empty set is "no protocol
	/// authenticates" — the account owns its mailboxes but cannot sign in
	/// anywhere.
	pub fn with_allowed_protocols(
		mut self,
		entries: impl IntoIterator<Item = (String, Vec<crate::config::Protocol>)>,
	) -> Self {
		self.allowed_protocols = entries
			.into_iter()
			.map(|(name, protocols)| {
				(
					name.to_ascii_lowercase(),
					protocols.into_iter().collect::<HashSet<_>>(),
				)
			})
			.collect();
		self
	}

	/// Whether `account` may authenticate through `protocol`. `None` when
	/// the account carries no allowlist (every protocol is admitted); a
	/// stored set decides otherwise.
	pub fn is_protocol_allowed(&self, account: &str, protocol: crate::config::Protocol) -> bool {
		self.allowed_protocols
			.get(&account.to_ascii_lowercase())
			.is_none_or(|set| set.contains(&protocol))
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

	/// Attach per-account storage quotas (account name → bytes).
	pub fn with_account_quotas(mut self, quotas: impl IntoIterator<Item = (String, u64)>) -> Self {
		self.account_quotas = quotas
			.into_iter()
			.map(|(name, bytes)| (name.to_ascii_lowercase(), bytes))
			.collect();
		self
	}

	/// Attach per-domain default storage quotas (domain → bytes).
	pub fn with_domain_quotas(mut self, quotas: impl IntoIterator<Item = (String, u64)>) -> Self {
		self.domain_quotas = quotas
			.into_iter()
			.map(|(domain, bytes)| (domain.to_ascii_lowercase(), bytes))
			.collect();
		self
	}

	/// Attach per-domain submission rate limits (domain → messages/min). The
	/// lookup walks the account's own addresses — the same approach
	/// [`Directory::quota_for`] takes — so the resolved domain is the one the
	/// address actually lives under, not the first one configured.
	pub fn with_domain_submission_limits(
		mut self,
		limits: impl IntoIterator<Item = (String, u32)>,
	) -> Self {
		self.domain_submission_limits = limits
			.into_iter()
			.map(|(domain, per_min)| (domain.to_ascii_lowercase(), per_min))
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

	/// The forwarding spec for an account: `(targets, keep_local)`.
	pub fn forwards(&self, account: &str) -> Option<(&[String], bool)> {
		self.forwards
			.get(&account.to_ascii_lowercase())
			.map(|(targets, keep)| (targets.as_slice(), *keep))
	}

	/// The storage quota for an account: its own quota, else the quota of a
	/// hosted domain it has an address in, else `None` (use the server default).
	pub fn quota_for(&self, account: &str) -> Option<u64> {
		let account = account.to_ascii_lowercase();
		if let Some(bytes) = self.account_quotas.get(&account) {
			return Some(*bytes);
		}
		if self.domain_quotas.is_empty() {
			return None;
		}
		self.accounts_by_address
			.iter()
			.filter(|(_, name)| name.eq_ignore_ascii_case(&account))
			.filter_map(|(addr, _)| addr.rsplit_once('@').map(|(_, domain)| domain))
			.find_map(|domain| self.domain_quotas.get(domain).copied())
	}

	/// The per-domain submission rate limit (messages/minute) for an
	/// account, derived from the domain of one of the account's own
	/// addresses. `None` when no per-domain limit covers the account; the
	/// caller (the SMTP session) is responsible for falling back to the
	/// server-wide limit, or to no limit at all.
	///
	/// Iterates the account's addresses rather than reading `domains[0]`:
	/// taking the first configured domain would assign every account to
	/// whichever domain happened to be configured first, and drop all of
	/// them the day that domain is removed. The address walk matches the
	/// approach [`Directory::quota_for`] takes for the same reason.
	pub fn submission_limit_for(&self, account: &str) -> Option<u32> {
		if self.domain_submission_limits.is_empty() {
			return None;
		}
		self.accounts_by_address
			.iter()
			.filter(|(_, name)| name.eq_ignore_ascii_case(account))
			.filter_map(|(addr, _)| addr.rsplit_once('@').map(|(_, domain)| domain))
			.find_map(|domain| self.domain_submission_limits.get(domain).copied())
	}

	/// Verify a login with its password, enforcing TOTP when the account has a
	/// secret: the last 6 digits of the password are the current TOTP code. This
	/// is a thin wrapper over [`Directory::authenticate_with_ip`] for callers
	/// without a client IP (app-password CIDR allowlists then never match).
	/// `protocol` tags the call site so an account restricted to a subset of
	/// protocols is rejected here when the caller is not in that subset.
	pub fn authenticate(
		&self,
		login: &str,
		password: &str,
		protocol: crate::config::Protocol,
	) -> Option<String> {
		self.authenticate_with_ip(login, password, None, protocol)
	}

	/// Every delivery address the directory resolves for `account`,
	/// case-preserved. Empty when the account is unknown — callers treat that
	/// as "no tenant membership" and skip per-tenant aggregates.
	pub fn addresses_for(&self, account: &str) -> Vec<String> {
		self.accounts_by_address
			.iter()
			.filter(|(_, owner)| owner.eq_ignore_ascii_case(account))
			.map(|(address, _)| address.clone())
			.collect()
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
	/// known account whose primary and every app password mismatch — both end in
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
	/// presented — never the plaintext password nor the TOTP code.
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
				// "disabled", and "wrong protocol" — none reveals that the
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

	/// Emit the audit event and bump the counter for one authentication
	/// attempt, with `outcome = None` for every failure path (unknown
	/// account, disabled account, wrong password, app-password CIDR miss,
	/// LDAP bind error) and `outcome = Some(account)` for a success. The
	/// counter is the derived view; the tracing event on the `epistle::auth`
	/// target is the primary record and is always emitted, including from
	/// tests that did not attach a metrics handle.
	fn record_auth_outcome(
		&self,
		login: &str,
		outcome: Option<&str>,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) {
		let event = match outcome {
			Some(_) => crate::api::AuditEvent::LoginSucceeded,
			None => crate::api::AuditEvent::LoginFailed,
		};
		crate::api::log_auth_attempt(event, login, outcome, ip, protocol);
		if let Some(metrics) = &self.metrics {
			match outcome {
				Some(_) => metrics.auth_login_succeeded(),
				None => metrics.auth_login_failed(),
			}
		}
	}

	/// The local credential path: primary password (with TOTP when set), then the
	/// account's app passwords. `None` when the login is unknown locally or no
	/// local secret matches. Split out so [`Directory::authenticate_with_ip`] can
	/// fall back to LDAP afterwards.
	fn authenticate_local(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
	) -> Option<String> {
		let (account, hash) = self.credentials(login)?;
		// Disabled check runs after the credential lookup (which lowercases the
		// bare-login path) but before any hashing — argon2id and SCRAM are both
		// skipped, which is the whole point. Lookup is O(1); the disabled set
		// is small in practice.
		if self.disabled.contains(&account) {
			return None;
		}
		// TOTP applies to the primary password only; strip and verify the code.
		let primary = match self.totp.get(&account) {
			Some(secret) => self.totp_strip(password, secret),
			None => Some(password),
		};
		if let Some(primary) = primary
			&& super::auth::verify_password(hash, primary)
		{
			return Some(account);
		}
		// Primary failed (or its TOTP did): try the account's app passwords. App
		// passwords are not subject to TOTP — they are independent secrets.
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		for app in self
			.app_passwords
			.get(&account)
			.map(Vec::as_slice)
			.unwrap_or(&[])
		{
			if app.admits(password, ip, now) {
				return Some(account.clone());
			}
		}
		None
	}

	/// Strip and verify the trailing 6-digit TOTP code from `password`, returning
	/// the remaining password on success, or `None` if the code is missing or
	/// wrong.
	fn totp_strip<'a>(&self, password: &'a str, secret: &str) -> Option<&'a str> {
		// `str::split_at` panics when its index is not on a UTF-8 character
		// boundary. Splitting by byte length is only safe when the trailing
		// six bytes are ASCII digits: a digit is a single-byte character that
		// cannot be a continuation byte, so the byte before them ends a
		// character by construction. This keeps the split safe for non-ASCII
		// passwords, which the policy is about to admit.
		let bytes = password.as_bytes();
		if bytes.len() < 7 || !bytes[bytes.len() - 6..].iter().all(u8::is_ascii_digit) {
			return None;
		}
		let split = bytes.len() - 6;
		let (pass, code) = password.split_at(split);
		let code: u32 = code.parse().ok()?;
		let secret_bytes = crate::totp::decode_base32_secret(secret)?;
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		crate::totp::verify(&secret_bytes, code, now).then_some(pass)
	}

	/// Attach SCRAM credentials (account name → stored credentials).
	pub fn with_scram(
		mut self,
		scram: impl IntoIterator<Item = (String, super::scram::ScramStored)>,
	) -> Self {
		self.scram = scram
			.into_iter()
			.map(|(name, stored)| (name.to_ascii_lowercase(), stored))
			.collect();
		self
	}

	/// Resolve a login to its SCRAM credentials, or `None` when the identity is
	/// unknown or has no SCRAM credentials.
	pub fn scram_credentials(&self, login: &str) -> Option<super::scram::ScramCredentials> {
		let account = if login.contains('@') {
			let address = Address::parse(login).ok()?;
			match self.resolve(&address) {
				Resolution::Account(account) => account,
				_ => return None,
			}
		} else {
			login.to_ascii_lowercase()
		};
		self.scram.get(&account)?.to_credentials()
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

	/// Resolve a login name (account name, or one of its addresses) to
	/// `(account, password_hash)`. `None` when the identity is unknown or
	/// the account has no password (receive-only).
	pub fn credentials(&self, login: &str) -> Option<(String, &str)> {
		let account = if login.contains('@') {
			let address = Address::parse(login).ok()?;
			match self.resolve(&address) {
				Resolution::Account(account) => account,
				_ => return None,
			}
		} else {
			let login = login.to_ascii_lowercase();
			if !self.password_hashes.contains_key(&login) {
				return None;
			}
			login
		};
		let hash = self.password_hashes.get(&account)?;
		Some((account, hash.as_str()))
	}

	/// Whether `address` belongs to `account`.
	pub fn owns_address(&self, account: &str, address: &Address) -> bool {
		let key = address.to_string().to_ascii_lowercase();
		if let Some(owner) = self.accounts_by_address.get(&key) {
			return owner == account;
		}
		// Sending as a multi-target alias: only a permitted sender may. With no
		// explicit senders, any member account may; a non-member never can.
		if let Some(spec) = self.aliases.get(&key) {
			let permitted = if spec.senders.is_empty() {
				&spec.members
			} else {
				&spec.senders
			};
			return permitted.iter().any(|addr| {
				self.accounts_by_address
					.get(&addr.to_ascii_lowercase())
					.is_some_and(|owner| owner == account)
			});
		}
		// Sending as an enabled masked email address: the owner only. Disabled
		// masks are absent from the map, so they fail closed the same way an
		// unknown address does.
		if let Some(owner) = self.masked_by_address.get(&key) {
			return owner == account;
		}
		false
	}

	/// Resolve a validated address.
	pub fn resolve(&self, address: &Address) -> Resolution {
		let local = address.local_part();
		// A domain alias resolves as its target domain.
		let domain = self
			.domain_aliases
			.get(address.domain())
			.map(String::as_str)
			.unwrap_or(address.domain());
		if !self.domains.contains(domain) {
			return Resolution::NotLocal;
		}
		let key = format!("{local}@{domain}").to_ascii_lowercase();
		if let Some(account) = self.accounts_by_address.get(&key) {
			return Resolution::Account(account.clone());
		}
		// Multi-target alias: fan out to its member accounts.
		if let Some(spec) = self.aliases.get(&key) {
			let accounts = spec
				.members
				.iter()
				.filter_map(|member| self.accounts_by_address.get(&member.to_ascii_lowercase()))
				.cloned()
				.collect();
			return Resolution::Alias(accounts);
		}
		// Enabled masked email address: deliver to its owner. Disabled masks
		// are absent here, so they reject identically to unknown users.
		if let Some(account) = self.masked_by_address.get(&key) {
			return Resolution::Account(account.clone());
		}
		// Sub-addressing: strip the tag and retry the base address.
		if let Some(base) = self.strip_subaddress(local, domain)
			&& let Some(account) = self.accounts_by_address.get(&base)
		{
			return Resolution::Account(account.clone());
		}
		// Catch-all: a domain may funnel its unknown local users to one account.
		if let Some(account) = self.catch_all.get(domain) {
			return Resolution::Account(account.clone());
		}
		Resolution::UnknownUser
	}

	/// The base `local@domain` key (lowercased) once the earliest sub-address
	/// separator and everything after it are removed, or `None` if the
	/// local part carries no tag.
	fn strip_subaddress(&self, local: &str, domain: &str) -> Option<String> {
		let cut = self
			.subaddress_separators
			.iter()
			.filter_map(|sep| local.find(*sep))
			.min()?;
		// A leading separator (e.g. `+tag`) leaves no base local-part.
		if cut == 0 {
			return None;
		}
		Some(format!("{}@{}", &local[..cut], domain).to_ascii_lowercase())
	}
}

#[cfg(test)]
#[path = "directory_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "directory_app_password_tests.rs"]
mod app_password_tests;

#[cfg(test)]
#[path = "directory_auth_audit_tests.rs"]
mod auth_audit_tests;

#[cfg(test)]
#[path = "directory_masked_tests.rs"]
mod masked_tests;

#[cfg(test)]
#[path = "directory_alias_tests.rs"]
mod alias_tests;

#[cfg(test)]
#[path = "directory_protocol_tests.rs"]
mod protocol_tests;

#[cfg(test)]
#[path = "directory_totp_tests.rs"]
mod totp_tests;

#[cfg(test)]
#[path = "directory_test_support.rs"]
mod test_support;
