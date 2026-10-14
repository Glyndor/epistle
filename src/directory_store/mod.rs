//! Runtime account store and the hot-reloadable directory handle.
//!
//! Static accounts come from the config file and never change at runtime;
//! dynamic accounts live in `<data_dir>/accounts.toml`, managed through the
//! API. The effective directory is rebuilt and swapped on every mutation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::config::{Account, Protocol};
use crate::directory_store::aliases::AliasStore;
use crate::password::Policy;
use crate::smtp::directory::Directory;
use crate::util::address_reason;

pub mod app_passwords;
pub use app_passwords::{AppPassword, AppPasswordStore};

pub mod aliases;
pub mod masked;
mod names;
pub(crate) use names::validate_name;
use names::with_safe_names;
mod account_views;
mod app_passwords_api;
mod masked_api;
mod reload_api;
pub use masked::{MaskedAddress, MaskedAddressStore, MaskedAddressView};

pub mod removal;
pub use removal::{QueuePolicy, Removed, remove_account};

pub mod sql;
pub use sql::{SqlAccount, load_sql_accounts};

pub mod ldap;
pub use ldap::{LdapAccount, LdapAuthenticator, load_ldap_accounts};

mod build;

#[path = "forward_catch_all_mutators.rs"]
mod forward_catch_all_mutators;
#[path = "mutators.rs"]
mod mutators;
pub mod scram_upgrade;

#[path = "password_policy_settings.rs"]
mod password_policy_settings;
#[path = "scram_settings.rs"]
mod scram_settings;
#[path = "set_totp.rs"]
mod set_totp;

/// Watcher that reloads the dynamic stores when a sibling process
/// (the CLI) writes them out of band. See [`file_watcher::FileWatcher`].
pub mod file_watcher;
pub use file_watcher::{ApiKeyReloader, FileWatcher};

mod collisions;
pub mod display_name;
mod mutate_store;
mod normalize;
pub use normalize::account_name;

/// Hot-swappable view of the directory. Cheap to clone; readers snapshot.
#[derive(Clone)]
pub struct DirectoryHandle {
	inner: Arc<RwLock<Arc<Directory>>>,
}

impl std::fmt::Debug for DirectoryHandle {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("DirectoryHandle")
	}
}

impl DirectoryHandle {
	/// Wrap an initial directory.
	pub fn new(directory: Directory) -> Self {
		DirectoryHandle {
			inner: Arc::new(RwLock::new(Arc::new(directory))),
		}
	}

	/// The current directory snapshot.
	pub fn current(&self) -> Arc<Directory> {
		Arc::clone(&self.inner.read().expect("directory lock"))
	}

	/// Replace the directory.
	pub fn replace(&self, directory: Directory) {
		*self.inner.write().expect("directory lock") = Arc::new(directory);
	}
}

/// Hook the directory calls back into when a cleartext authentication
/// succeeds against a dynamic account whose stored SCRAM verifier is below
/// the current iteration constant. See [`crate::directory_store::scram_upgrade`]
/// for the trait + no-op default + store impl; this file only re-exports
/// them so `mod.rs` stays under the per-file code-line budget.
pub use crate::directory_store::scram_upgrade::{NoopScramUpgrader, ScramUpgrader};

/// A dynamic account as persisted in `accounts.toml`. `Default` is an
/// empty record for test fixtures and API constructors to fill with
/// `..DynamicAccount::default()`; it is not a valid account on its own
/// (`AccountStore::add` requires a password hash and an address).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicAccount {
	/// Account login name (the local part used by IMAP/SMTP AUTH, without
	/// the `@domain`). Lowercase ASCII, no leading hyphen; validated by
	/// `AccountStore::add`.
	pub name: String,
	/// Delivery addresses (full `user@domain`) this account owns. At least
	/// one, all in configured domains.
	pub addresses: Vec<String>,
	/// Argon2id hash of the account's password (the encoding used by
	/// `smtp::auth::hash_password`). Stored, never the plaintext.
	pub password_hash: String,
	/// SCRAM credentials, derived from the password at set time (RFC 5802).
	#[serde(default)]
	pub scram: Option<crate::smtp::scram::ScramStored>,
	/// Base32 TOTP secret for two-factor auth (RFC 6238). Absent disables 2FA.
	#[serde(default)]
	pub totp_secret: Option<String>,
	/// Account is administratively disabled (kept on disk; never
	/// authenticates). Set by SCIM `active: false` and other paths that need
	/// to suspend an account without removing its mailbox.
	#[serde(default)]
	pub disabled: bool,
	/// Storage quota (bytes) for this account. `None` (the default, and the
	/// value on `accounts.toml` files written before the field existed)
	/// falls back to the domain quota, then the server default, exactly the
	/// way static `Account::quota_bytes = None` does. IMAP `GETQUOTAROOT` and
	/// the delivery quota check both read the rebuilt directory's quota map.
	#[serde(default)]
	pub quota_bytes: Option<u64>,
	/// Restrict which authentication protocols this account may sign in
	/// through. `None` (the default) means every protocol the directory
	/// knows about — the pre-restriction behaviour. When set, only the
	/// listed protocols authenticate this account; every other path rejects
	/// identically to an unknown login, so the wire response never reveals
	/// that the account exists.
	#[serde(default)]
	pub allowed_protocols: Option<Vec<Protocol>>,
	/// External addresses this account's mail is also forwarded to.
	/// Empty (the default) disables forwarding. Mirrors the static
	/// `Account::forward` field; dynamic forwards chain onto static ones
	/// in the directory builder so the two pools compose at delivery time.
	#[serde(default)]
	pub forward: Vec<String>,
	/// Domains for which this account receives mail addressed to otherwise
	/// unknown local users (catch-all). Empty (the default) opts out; mirrors
	/// the static `Account::catch_all` field.
	#[serde(default)]
	pub catch_all: Vec<String>,
	/// The person's name, free text used as the sender name (JMAP
	/// `Identity.name`, the `From` that `/api/v1/send` builds). Stored as
	/// given (trimmed), never lowercased; `None` when unset. Checked by
	/// [`display_name::validate`].
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub display_name: Option<String>,
	/// Whether messages the account submits are saved to its `Sent`
	/// folder. `None` (the default and the value on `accounts.toml`
	/// files written before the field existed) defaults to "on"; an
	/// explicit `Some(false)` disables the save for this account
	/// unless an app password on the credential overrides it.
	/// Per-request (`/api/v1/send`, JMAP `EmailSubmission`) and
	/// per-credential (app password) overrides win over the
	/// account-wide setting.
	#[serde(default)]
	pub save_sent: Option<bool>,
}

impl DynamicAccount {
	/// Build an account from a plaintext password, deriving the argon2id hash
	/// and SCRAM-SHA-256 credentials (fresh random salt,
	/// [`crate::smtp::scram::SCRAM_ITERATIONS`] rounds). When
	/// `scram_enabled` is `false`, the SCRAM verifier is omitted (`None`);
	/// a future password change with `scram_enabled` `false` keeps it
	/// `None`.
	///
	/// `policy` decides whether `password` is NFKC-normalised before hashing
	/// and SCRAM derivation. With `Policy::ASCII_ONLY` (the default) the
	/// input is hashable as-is; with `Policy::unicode` the prepare step
	/// canonicalises it (RFC 8265 OpaqueString), so a password set with one
	/// keyboard verifies from another.
	pub fn with_password(
		name: String,
		addresses: Vec<String>,
		password: &str,
		policy: &Policy,
		scram_enabled: bool,
	) -> Result<Self, StoreError> {
		let prepared = policy
			.prepare(password)
			.map_err(|rejection| StoreError::Invalid(rejection.message().to_string()))?;
		let password_hash = crate::smtp::auth::hash_password(prepared.as_ref())
			.map_err(|_| StoreError::Invalid("cannot hash password".to_string()))?;
		let scram = if scram_enabled {
			let stored = crate::smtp::scram::ScramStored::with_fresh_salt(prepared.as_ref())
				.ok_or_else(|| StoreError::Invalid("cannot generate salt".to_string()))?;
			Some(stored)
		} else {
			None
		};
		Ok(DynamicAccount {
			name,
			addresses,
			password_hash,
			scram,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			forward: Vec::new(),
			catch_all: Vec::new(),
			display_name: None,
			save_sent: None,
		})
	}
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DynamicFile {
	#[serde(default)]
	accounts: Vec<DynamicAccount>,
}

/// Errors from the account store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
	/// The supplied account data is invalid: malformed address, missing
	/// addresses, an address outside the configured domains, a bad account
	/// name, or a malformed `accounts.toml`. The string carries the
	/// underlying reason.
	#[error("invalid account: {0}")]
	Invalid(String),
	/// An account or address with this name already exists in the store.
	/// Carries the conflicting name or address.
	#[error("account {0} already exists")]
	Duplicate(String),
	/// No dynamic account with the requested name. Carries the missing name.
	#[error("no such dynamic account: {0}")]
	NotFound(String),
	/// The per-account cap on masked addresses would be exceeded. Carries
	/// the configured `max` so the API can render the limit to the operator.
	#[error("masked-address limit reached: {max}")]
	LimitReached {
		/// The configured cap.
		max: usize,
	},
	/// Reading or writing the `accounts.toml` / `app_passwords.toml` /
	/// `masked.json` sidecar files failed. The wrapped `std::io::Error`
	/// carries the cause.
	#[error("storage failure: {0}")]
	Io(#[from] std::io::Error),
	/// The per-account Bayesian purge could not be completed. The
	/// dynamic-account row is left on disk so a retry can drop the
	/// corpus rows and finish the removal; this prevents a recreated
	/// account from inheriting the previous user's training.
	#[error("bayes purge failed for {account}: {source}")]
	BayesPurge {
		/// The account whose per-scope rows could not be dropped.
		account: String,
		/// The underlying `sqlx::Error` returned by the corpus purge.
		source: sqlx::Error,
	},
}

/// The mutable account store: static accounts + persisted dynamic ones.
pub struct AccountStore {
	path: PathBuf,
	domains: Vec<String>,
	domain_aliases: std::collections::HashMap<String, String>,
	static_accounts: Vec<Account>,
	/// Default storage quota (bytes) per domain.
	domain_quotas: std::collections::HashMap<String, u64>,
	/// Per-domain submission rate limit (messages/min) applied to authenticated
	/// senders in that domain. Mirrors `domain_quotas` in shape and lifecycle.
	domain_submission_limits: std::collections::HashMap<String, u32>,
	/// Multi-target aliases from the static configuration.
	aliases: Vec<crate::config::Alias>,
	/// App passwords (secondary mail credentials) keyed by account; the
	/// in-memory mirror of `app_passwords.toml`. Mutators keep disk and
	/// memory in sync, so a removal takes effect on the next rebuild
	/// without a server restart.
	app_passwords: RwLock<Vec<(String, AppPassword)>>,
	dynamic: RwLock<Vec<DynamicAccount>>,
	/// Accounts loaded from the SQL directory backend, refreshed periodically.
	/// Static config and dynamic accounts take precedence over these on a name
	/// or address conflict.
	sql_accounts: RwLock<Vec<SqlAccount>>,
	/// Accounts loaded from the LDAP directory backend, refreshed periodically.
	/// Lowest precedence: static, dynamic and SQL accounts all win on conflict.
	ldap_accounts: RwLock<Vec<LdapAccount>>,
	/// Live LDAP authenticator (a worker thread), shared into every rebuilt
	/// directory so per-request binds work after a refresh.
	ldap_auth: Option<Arc<LdapAuthenticator>>,
	/// Per-account masked email addresses, persisted to `masked.json`.
	/// Wrapped in `Arc<RwLock<_>>` so the API can share the same handle and
	/// mutate without going through `AccountStore`'s mutators.
	masked: Arc<RwLock<MaskedAddressStore>>,
	aliases_disabled: Arc<RwLock<AliasStore>>,
	/// Shared ban store consulted before any password hashing and updated
	/// on every authentication outcome. Threaded into every rebuilt
	/// directory by [`AccountStore::with_ban_store`]. `None` in deployments
	/// without `[database]`; the per-connection three-strikes counters are
	/// the only defence on those.
	ban_store: Option<Arc<dyn crate::antispam::bans::BanStore>>,
	/// Shared metrics handle for the audit counters
	/// (`auth_login_succeeded` / `auth_login_failed`). Threaded into every
	/// rebuilt directory via [`AccountStore::with_metrics`] so the SMTP,
	/// IMAP, ManageSieve, WebDAV, API and OAuth paths bump the same counters.
	/// `None` in unit tests that do not exercise the counters — the
	/// directory still emits the structured tracing event regardless.
	metrics: Option<Arc<crate::metrics::Metrics>>,
	/// Callback wired into every rebuilt directory to upgrade a dynamic
	/// account's SCRAM verifier when its stored iteration count is below
	/// the current constant. Set by the `serve` builder with an
	/// `Arc<Self>` so the directory's upgrade writes round-trip to the
	/// store; left as a no-op until then so unit tests that build a store
	/// without a runtime never observe a real write.
	scram_upgrader: Arc<dyn ScramUpgrader>,
	/// Whether SCRAM-SHA-256 derivation/storage is enabled (the `[auth] scram`
	/// knob). `true` is the historical default: account-create and
	/// password-change paths derive a verifier and store it; the SCRAM
	/// upgrade path is a no-op when an account has none. `false` skips
	/// derivation entirely; the next password change of an account that
	/// already has a verifier drops it because the mutator passes `None`.
	scram_enabled: bool,
	/// Runtime password policy (default `ASCII_ONLY`; production wiring
	/// sets it from `[auth] unicode_passwords` via `with_password_policy`).
	password_policy: Policy,
	/// At-rest encryption for the TOTP secret (see `set_totp.rs`).
	crypto: crate::storage::MessageCrypto,
	handle: DirectoryHandle,
}

impl AccountStore {
	/// Load the store, merge with the static configuration and build the
	/// initial directory.
	pub fn open(
		data_dir: &Path,
		domains: Vec<String>,
		domain_aliases: std::collections::HashMap<String, String>,
		static_accounts: Vec<Account>,
	) -> Result<Self, StoreError> {
		let path = data_dir.join("accounts.toml");
		let dynamic: DynamicFile = match std::fs::read_to_string(&path) {
			Ok(text) => normalize::file(
				toml::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?,
			),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => DynamicFile::default(),
			Err(error) => return Err(error.into()),
		};

		// App passwords are an optional sidecar; a missing file is an empty set.
		let app_passwords = RwLock::new(AppPasswordStore::open(data_dir)?.entries().collect());

		let masked = MaskedAddressStore::open(data_dir)?;

		let store = AccountStore {
			path,
			domains,
			domain_aliases,
			static_accounts,
			domain_quotas: std::collections::HashMap::new(),
			domain_submission_limits: std::collections::HashMap::new(),
			aliases: Vec::new(),
			app_passwords,
			dynamic: RwLock::new(dynamic.accounts),
			sql_accounts: RwLock::new(Vec::new()),
			ldap_accounts: RwLock::new(Vec::new()),
			ldap_auth: None,
			masked: Arc::new(RwLock::new(masked)),
			aliases_disabled: Arc::new(RwLock::new(AliasStore::open(data_dir)?)),
			ban_store: None,
			metrics: None,
			scram_upgrader: Arc::new(NoopScramUpgrader) as Arc<dyn ScramUpgrader>,
			scram_enabled: true,
			password_policy: Policy::ASCII_ONLY,
			crypto: crate::storage::MessageCrypto::disabled(),
			handle: DirectoryHandle::new(Directory::default()),
		};
		store.handle.replace(store.build_directory());
		Ok(store)
	}

	/// Set the per-domain default storage quotas and rebuild the directory.
	pub fn with_domain_quotas(mut self, quotas: std::collections::HashMap<String, u64>) -> Self {
		self.domain_quotas = quotas;
		self.handle.replace(self.build_directory());
		self
	}

	/// Set the per-domain submission rate limits (messages/min) and rebuild
	/// the directory.
	pub fn with_domain_submission_limits(
		mut self,
		limits: std::collections::HashMap<String, u32>,
	) -> Self {
		self.domain_submission_limits = limits;
		self.handle.replace(self.build_directory());
		self
	}

	/// Set the multi-target aliases and rebuild the directory.
	pub fn with_aliases(mut self, aliases: Vec<crate::config::Alias>) -> Self {
		self.aliases = aliases;
		self.handle.replace(self.build_directory());
		self
	}

	/// Seed the SQL-sourced accounts at construction and rebuild the directory
	/// (builder form, for startup wiring).
	pub fn with_sql_accounts(self, accounts: Vec<SqlAccount>) -> Self {
		self.set_sql_accounts(accounts);
		self
	}

	/// Replace the SQL-sourced accounts and rebuild the directory. Called by the
	/// background refresh task on an `Arc<AccountStore>`; static and dynamic
	/// accounts keep precedence on conflict.
	pub fn set_sql_accounts(&self, accounts: Vec<SqlAccount>) {
		let accounts = with_safe_names(accounts, "sql", |account| &account.name);
		*self.sql_accounts.write().expect("store lock") = accounts;
		self.handle.replace(self.build_directory());
	}

	/// Attach the live LDAP authenticator at construction and rebuild the
	/// directory so per-request LDAP binds are wired in (builder form).
	pub fn with_ldap_authenticator(mut self, ldap: Arc<LdapAuthenticator>) -> Self {
		self.ldap_auth = Some(ldap);
		self.handle.replace(self.build_directory());
		self
	}

	/// Attach the shared metrics handle so every directory rebuilt from
	/// this point on bumps the audit counters (`auth_login_succeeded` /
	/// `auth_login_failed`) on every password-based authentication
	/// attempt. The structured tracing event is always emitted regardless
	/// — the counter is a derived view.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self.handle.replace(self.build_directory());
		self
	}

	/// Attach the shared ban store consulted on every password
	/// authentication. `None` (the default) keeps the per-connection
	/// three-strikes counters as the only defence; with `[database]`
	/// configured the `serve` builder wires in a [`PgBanStore`].
	///
	/// [`PgBanStore`]: crate::antispam::bans::PgBanStore
	pub fn with_ban_store(mut self, store: Arc<dyn crate::antispam::bans::BanStore>) -> Self {
		self.ban_store = Some(store);
		self.handle.replace(self.build_directory());
		self
	}

	/// The ban store attached to this store, when one is.
	pub fn ban_store(&self) -> Option<&Arc<dyn crate::antispam::bans::BanStore>> {
		self.ban_store.as_ref()
	}

	/// Replace the LDAP-sourced resolution accounts and rebuild the directory.
	/// Called by the background refresh task; static, dynamic and SQL accounts all
	/// keep precedence on conflict.
	pub fn set_ldap_accounts(&self, accounts: Vec<LdapAccount>) {
		let accounts = with_safe_names(accounts, "ldap", |account| &account.name);
		*self.ldap_accounts.write().expect("store lock") = accounts;
		self.handle.replace(self.build_directory());
	}

	/// The hot-reloadable handle shared with servers and delivery.
	pub fn handle(&self) -> DirectoryHandle {
		self.handle.clone()
	}

	/// Add a dynamic account. `password_hash` must already be argon2id.
	pub fn add(&self, mut account: DynamicAccount) -> Result<(), StoreError> {
		account.name = normalize::account_name(&account.name);
		normalize::account(&mut account);
		account.display_name = display_name::stored(account.display_name.as_deref())?;
		self.mutate_store(|state| {
			validate_name(&account.name)?;
			if account.addresses.is_empty() {
				return Err(StoreError::Invalid("addresses must not be empty".into()));
			}
			for raw in &account.addresses {
				let address = address_reason::parse(raw).map_err(StoreError::Invalid)?;
				if !self
					.domains
					.iter()
					.any(|domain| domain.eq_ignore_ascii_case(address.domain()))
				{
					return Err(StoreError::Invalid(address_reason::not_handled(
						address.domain(),
					)));
				}
			}
			let name_taken = self
				.static_accounts
				.iter()
				.map(|existing| existing.name.as_str())
				.chain(state.accounts.iter().map(|existing| existing.name.as_str()))
				.any(|existing| existing == account.name);
			if name_taken {
				return Err(StoreError::Duplicate(account.name.clone()));
			}
			for raw in &account.addresses {
				if self.address_taken(&state.accounts, None, raw) {
					return Err(StoreError::Duplicate(raw.to_string()));
				}
			}
			state.accounts.push(account);
			Ok(())
		})?;
		Ok(())
	}

	/// Replace a dynamic account in place, preserving its position in the
	/// on-disk list. Used by SCIM `PUT` (which is "replace the whole user"
	/// in SCIM terms) without churning the file. `NotFound` if no
	/// dynamic account carries `name`; `Duplicate` if the replacement's
	/// addresses collide with another account (including itself if the
	/// new list is unchanged — `add` short-circuits the collision check
	/// on self, but a fresh `add` after `remove` doesn't, so we do the
	/// same dance here).
	pub fn replace_account(
		&self,
		name: &str,
		replacement: DynamicAccount,
	) -> Result<(), StoreError> {
		self.mutate_store(|state| {
			let slot = state
				.accounts
				.iter()
				.position(|existing| existing.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			let mut fresh = replacement;
			fresh.name = name.to_string();
			normalize::account(&mut fresh);
			fresh.display_name = display_name::stored(fresh.display_name.as_deref())?;
			let mut known_addresses: Vec<String> = self
				.static_accounts
				.iter()
				.flat_map(|existing| existing.addresses.iter())
				.chain(
					state
						.accounts
						.iter()
						.enumerate()
						.filter(|(index, _)| *index != slot)
						.flat_map(|(_, existing)| existing.addresses.iter()),
				)
				.map(|address| crate::util::address::normalize(address))
				.collect();
			known_addresses.sort();
			for raw in &fresh.addresses {
				if known_addresses.binary_search(raw).is_ok() {
					return Err(StoreError::Duplicate(raw.to_string()));
				}
			}
			state.accounts[slot] = fresh;
			Ok(())
		})?;
		Ok(())
	}

	fn build_directory(&self) -> Directory {
		let dynamic = self.dynamic.read().expect("store lock");
		let sql = self.sql_accounts.read().expect("store lock");
		let ldap = self.ldap_accounts.read().expect("store lock");
		let address_accounts =
			build::address_accounts(&ldap, &sql, &self.static_accounts, &dynamic);
		let allowed_protocols =
			build::allowed_protocols(&self.static_accounts, &dynamic).collect::<Vec<_>>();
		let hashes = build::password_hashes(&sql, &self.static_accounts, &dynamic);
		let catch_all = build::catch_all(&self.static_accounts, &dynamic);
		let scram = build::scram(&dynamic);
		let totp = build::totp(&dynamic, &self.crypto);
		// Disabled accounts are passed through to the directory as a name
		// set so `authenticate_local` can reject them before any password
		// work runs. The set rebuilds on every directory swap, mirroring
		// how totp, scram and quotas are wired.
		let disabled = build::disabled(&dynamic);
		// Quotas feed into the directory as (name, bytes) pairs. Static
		// chains first so a dynamic quota can overwrite a static one when
		// the names collide (the directory's HashMap keeps the last writer,
		// mirroring how addresses and password hashes merge).
		let account_quotas = self
			.static_accounts
			.iter()
			.filter_map(|account| {
				account
					.quota_bytes
					.map(|bytes| (account.name.clone(), bytes))
			})
			.chain(build::quota_bytes(&dynamic));
		// Per-account `save_sent` overrides are dynamic-only (static
		// accounts do not carry the field today; the operator can edit
		// `mail.toml` to disable saving if the static-account default is
		// ever added). The map omits accounts whose setting is `None`,
		// so the saver falls back to the default ("on").
		let save_sent = build::save_sent(&dynamic);
		let forwards = build::forwards(&self.static_accounts, &dynamic);
		let disabled_lock = self.aliases_disabled.read().expect("aliases lock");
		let aliases = self.aliases.iter().map(|alias| {
			(
				alias.address.clone(),
				crate::smtp::directory::AliasSpec {
					members: alias.members.clone(),
					senders: alias.senders.clone(),
					hidden: alias.hidden,
					list_id: alias.list_id.clone(),
				},
			)
		});
		let aliases = aliases.filter(|(address, _)| !disabled_lock.is_disabled(address));
		// Masked email addresses: only enabled ones feed the directory so a
		// disabled mask rejects like an unknown user and the SMTP `owns_address`
		// check stays fail-closed.
		let masked = self
			.masked
			.read()
			.expect("masked lock")
			.entries()
			.collect::<Vec<_>>();
		let mut dir = Directory::new(self.domains.iter().cloned(), address_accounts)
			.with_password_hashes(hashes)
			.with_catch_all(catch_all)
			.with_domain_aliases(self.domain_aliases.clone())
			.with_scram(scram)
			.with_totp(totp)
			.with_disabled(disabled)
			.with_account_quotas(account_quotas)
			.with_domain_quotas(self.domain_quotas.clone())
			.with_domain_submission_limits(self.domain_submission_limits.clone())
			.with_forwards(forwards)
			.with_save_sent(save_sent)
			.with_aliases(aliases)
			.with_app_passwords(
				self.app_passwords
					.read()
					.expect("app-passwords lock")
					.iter()
					.cloned(),
			)
			.with_ldap(self.ldap_auth.clone())
			.with_masked(masked)
			.with_allowed_protocols(allowed_protocols);
		if let Some(metrics) = self.metrics.clone() {
			dir = dir.with_metrics(metrics);
		}
		if let Some(ban_store) = self.ban_store.clone() {
			dir = dir.with_ban_store(ban_store);
		}
		dir = dir.with_scram_upgrader(self.scram_upgrader.clone());
		dir = dir.with_password_policy(self.password_policy);
		dir
	}
}

/// Manual Debug so the `ScramUpgrader` trait object can sit in the
/// `Directory` struct (which derives Debug) without forcing every
/// implementor to depend on the store's internals.
impl std::fmt::Debug for AccountStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AccountStore")
			.field("path", &self.path)
			.field("domains", &self.domains)
			.field(
				"dynamic_count",
				&self.dynamic.read().map(|g| g.len()).unwrap_or(0),
			)
			.finish_non_exhaustive()
	}
}

#[cfg(test)]
#[path = "account_mutators_tests.rs"]
mod account_mutators_tests;

#[cfg(test)]
#[path = "cross_handle_tests.rs"]
mod cross_handle_tests;

#[cfg(test)]
#[path = "lowercase_tests.rs"]
mod lowercase_tests;
