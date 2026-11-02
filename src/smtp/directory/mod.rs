//! Recipient resolution: which account, if any, receives an address.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use super::address::Address;
use crate::password::Policy;
use crate::util::address::normalize;

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
	/// Hosted domains switched off: mail for them is rejected like mail for
	/// an unknown user and nobody may send as an address in them.
	disabled_domains: HashSet<String>,
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
	/// Per-account `save_sent` preference for outbound submission. `None`
	/// (the account carries no preference) means "on" by default; an
	/// explicit `Some(false)` disables the save for this account. A
	/// per-request or per-app-password override wins over the
	/// account-wide setting; the account-wide setting only applies when
	/// neither override exists.
	account_save_sent: HashMap<String, bool>,
	/// Per-account external forwarding: `(targets, keep_local)`. Mail for the
	/// account is also queued to each target; `keep_local` keeps the local copy.
	forwards: HashMap<String, (Vec<String>, bool)>,
	/// Multi-target aliases, keyed by lowercased alias address.
	aliases: HashMap<String, AliasSpec>,
	/// Secondary app passwords per account name. Each entry is tried when the
	/// primary password check fails (see [`Directory::authenticate_with_ip`]).
	app_passwords: HashMap<String, Vec<crate::directory_store::AppPassword>>,
	/// The most app passwords any one account holds. A refusal does the work of
	/// a primary password plus this many, so it costs the same for every login.
	max_app_passwords: usize,
	/// Optional live LDAP/AD authenticator. Consulted only when the local
	/// credential path yields no match, so local and SQL accounts never incur an
	/// LDAP round trip (see [`Directory::authenticate_with_ip`]).
	ldap: Option<std::sync::Arc<crate::directory_store::LdapAuthenticator>>,
	/// Enabled masked email addresses (lowercased address → owning account).
	/// Disabled masks are not present here, so they reject exactly like an
	/// unknown user (the directory never reveals that one once existed).
	masked_by_address: HashMap<String, String>,
	/// Masked addresses that are switched off (lowercased). Only
	/// [`Directory::is_paused`] reads them: resolution treats them as unknown.
	masked_paused: std::collections::HashSet<String>,
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
	/// `[database]`; those fall back to the per-connection three-strikes
	/// counters that the listeners already maintain.
	ban_store: Option<std::sync::Arc<dyn crate::antispam::bans::BanStore>>,
	/// Optional callback invoked after a successful cleartext (PLAIN/LOGIN)
	/// authentication to a dynamic account whose stored SCRAM verifier was
	/// derived with fewer than the current iteration constant. The store
	/// regenerates the verifier with a fresh salt and persists it, so the
	/// next exchange pays the full cost. `None` in unit tests that do not
	/// exercise the upgrade path.
	scram_upgrader: Option<std::sync::Arc<dyn crate::directory_store::ScramUpgrader>>,
	/// Runtime password policy. Defaults to the ASCII-only policy; the
	/// `serve` builder wires it from the store's `password_policy` so a
	/// non-ASCII candidate set under `[auth] unicode_passwords = true`
	/// verifies consistently with the bytes hashed at set-time.
	password_policy: Policy,
	/// Bounds how many password checks run at once (see `hash_gate/mod.rs`).
	hash_gate: std::sync::Arc<hash_gate::HashGate>,
	/// Test-only SCRAM credential-lookup counter. The ban tests inject
	/// a fresh `Arc<AtomicUsize>` per test via
	/// `with_scram_lookup_counter` so the delta they assert is
	/// isolated from any other test in the same `cargo test` process.
	#[cfg(test)]
	scram_lookup_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
	/// Test-only counts of the stand-in work done for logins that have no
	/// credential of their own (see `scram/tests/test_counter.rs`).
	#[cfg(test)]
	decoy_counters:
		Option<std::sync::Arc<crate::smtp::directory::tests::bans::decoy_counters::DecoyCounters>>,
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
				.map(|(address, account)| (normalize(&address), account))
				.collect(),
			password_hashes: HashMap::new(),
			// The `+` separator is the de-facto standard, enabled by default.
			subaddress_separators: vec!['+'],
			catch_all: HashMap::new(),
			domain_aliases: HashMap::new(),
			disabled_domains: HashSet::new(),
			scram: HashMap::new(),
			totp: HashMap::new(),
			disabled: HashSet::new(),
			account_quotas: HashMap::new(),
			domain_quotas: HashMap::new(),
			domain_submission_limits: HashMap::new(),
			forwards: HashMap::new(),
			aliases: HashMap::new(),
			app_passwords: HashMap::new(),
			max_app_passwords: 0,
			account_save_sent: HashMap::new(),
			ldap: None,
			masked_by_address: HashMap::new(),
			masked_paused: std::collections::HashSet::new(),
			metrics: None,
			allowed_protocols: HashMap::new(),
			ban_store: None,
			scram_upgrader: None,
			password_policy: Policy::ASCII_ONLY,
			hash_gate: hash_gate::HashGate::shared(),
			#[cfg(test)]
			scram_lookup_counter: None,
			#[cfg(test)]
			decoy_counters: None,
		}
	}

	/// The member accounts of an alias address, or `None` when the address is
	/// not an alias or its membership is hidden (privacy).
	pub fn alias_members(&self, address: &str) -> Option<Vec<String>> {
		let spec = self.aliases.get(&normalize(address))?;
		(!spec.hidden).then(|| spec.members.clone())
	}

	/// The forwarding spec for an account: `(targets, keep_local)`.
	pub fn forwards(&self, account: &str) -> Option<(&[String], bool)> {
		self.forwards
			.get(&account.to_ascii_lowercase())
			.map(|(targets, keep)| (targets.as_slice(), *keep))
	}

	/// The list of domains the server accepts mail for, lowercased. Used
	/// by the report-ingest hook to recognise `postmaster@<domain>` and
	/// `tlsrpt@<domain>` recipients against the served domain set.
	pub fn domains(&self) -> Vec<String> {
		self.domains.iter().cloned().collect()
	}

	/// Whether `domain` is hosted here, directly or as an alias domain:
	/// the domains the DKIM key is published for.
	pub fn hosts_domain(&self, domain: &str) -> bool {
		let domain = domain.to_ascii_lowercase();
		self.domains.contains(&domain) || self.domain_aliases.contains_key(&domain)
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
		if self.domain_disabled(address.domain()) {
			return false;
		}
		let key = normalize(&address.to_string());
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
					.get(&normalize(addr))
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
}

mod access;
mod builder;

mod limits;

mod resolve;

mod list_fields;

#[cfg(test)]
pub(crate) mod tests;

mod scram;

mod scram_upgrade;

pub mod bans;

mod credential;

mod local;

pub(crate) mod hash_gate;

mod gate;
pub use gate::{Proof, ScramPlan, ScramRefusal, bearer_proof};

#[cfg(test)]
mod fixtures;
#[cfg(test)]
use fixtures::test_support;
#[cfg(test)]
pub(crate) use fixtures::{gate_fixture, send_as_fixture};
