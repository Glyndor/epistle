//! Runtime account store and the hot-reloadable directory handle.
//!
//! Static accounts come from the config file and never change at runtime;
//! dynamic accounts live in `<data_dir>/accounts.toml`, managed through the
//! API. The effective directory is rebuilt and swapped on every mutation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::config::Account;
use crate::smtp::address::Address;
use crate::smtp::directory::Directory;

pub mod app_passwords;
pub use app_passwords::{AppPassword, AppPasswordStore};

pub mod masked;
mod names;
use names::{validate_name, with_safe_names};
mod masked_api;
pub use masked::{MaskedAddress, MaskedAddressStore, MaskedAddressView};

pub mod sql;
pub use sql::{SqlAccount, load_sql_accounts};

pub mod ldap;
pub use ldap::{LdapAccount, LdapAuthenticator, load_ldap_accounts};

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

/// A dynamic account as persisted in `accounts.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl DynamicAccount {
	/// Build an account from a plaintext password, deriving the argon2id hash
	/// and SCRAM-SHA-256 credentials (fresh random salt, RFC 7677 ≥4096 rounds).
	pub fn with_password(
		name: String,
		addresses: Vec<String>,
		password: &str,
	) -> Result<Self, StoreError> {
		let password_hash = crate::smtp::auth::hash_password(password)
			.map_err(|_| StoreError::Invalid("cannot hash password".to_string()))?;
		let scram = crate::smtp::scram::ScramStored::with_fresh_salt(password)
			.ok_or_else(|| StoreError::Invalid("cannot generate salt".to_string()))?;
		Ok(DynamicAccount {
			name,
			addresses,
			password_hash,
			scram: Some(scram),
			totp_secret: None,
			disabled: false,
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
	/// App passwords (secondary mail credentials) keyed by account, loaded from
	/// `app_passwords.toml` at open time.
	app_passwords: Vec<(String, AppPassword)>,
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
	/// Shared metrics handle for the audit counters
	/// (`auth_login_succeeded` / `auth_login_failed`). Threaded into every
	/// rebuilt directory via [`AccountStore::with_metrics`] so the SMTP,
	/// IMAP, ManageSieve, WebDAV, API and OAuth paths bump the same counters.
	/// `None` in unit tests that do not exercise the counters — the
	/// directory still emits the structured tracing event regardless.
	metrics: Option<Arc<crate::metrics::Metrics>>,
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
			Ok(text) => {
				toml::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => DynamicFile::default(),
			Err(error) => return Err(error.into()),
		};

		// App passwords are an optional sidecar; a missing file is an empty set.
		let app_passwords = AppPasswordStore::open(data_dir)?.entries().collect();

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
			metrics: None,
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
	pub fn add(&self, account: DynamicAccount) -> Result<(), StoreError> {
		validate_name(&account.name)?;
		if account.addresses.is_empty() {
			return Err(StoreError::Invalid("addresses must not be empty".into()));
		}
		for raw in &account.addresses {
			let address = Address::parse(raw)
				.map_err(|_| StoreError::Invalid(format!("invalid address {raw}")))?;
			if !self
				.domains
				.iter()
				.any(|domain| domain.eq_ignore_ascii_case(address.domain()))
			{
				return Err(StoreError::Invalid(format!(
					"address {raw} is not in a configured domain"
				)));
			}
		}

		let mut dynamic = self.dynamic.write().expect("store lock");
		let name_taken = self
			.static_accounts
			.iter()
			.map(|existing| existing.name.as_str())
			.chain(dynamic.iter().map(|existing| existing.name.as_str()))
			.any(|existing| existing == account.name);
		if name_taken {
			return Err(StoreError::Duplicate(account.name.clone()));
		}
		let mut known_addresses: Vec<String> = self
			.static_accounts
			.iter()
			.flat_map(|existing| existing.addresses.iter())
			.chain(
				dynamic
					.iter()
					.flat_map(|existing| existing.addresses.iter()),
			)
			.map(|address| address.to_ascii_lowercase())
			.collect();
		known_addresses.sort();
		for raw in &account.addresses {
			if known_addresses
				.binary_search(&raw.to_ascii_lowercase())
				.is_ok()
			{
				return Err(StoreError::Duplicate(raw.clone()));
			}
		}

		dynamic.push(account);
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Remove a dynamic account. Static accounts cannot be removed here.
	pub fn remove(&self, name: &str) -> Result<(), StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let before = dynamic.len();
		dynamic.retain(|account| account.name != name);
		if dynamic.len() == before {
			return Err(StoreError::NotFound(name.to_string()));
		}
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Replace the password hash (and SCRAM credentials) of a dynamic account.
	pub fn set_password_hash(
		&self,
		name: &str,
		hash: String,
		scram: Option<crate::smtp::scram::ScramStored>,
	) -> Result<(), StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		account.password_hash = hash;
		account.scram = scram;
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Set or clear a dynamic account's base32 TOTP secret (RFC 6238).
	pub fn set_totp(&self, name: &str, secret: Option<String>) -> Result<(), StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		account.totp_secret = secret;
		self.persist(&dynamic)?;
		Ok(())
	}

	/// Enable or disable a dynamic account (the SCIM `active` flag). The
	/// account stays on disk and continues to own its mailboxes, but
	/// authentication rejects it while disabled. Returns the previous state
	/// so callers can detect a no-op.
	pub fn set_disabled(&self, name: &str, disabled: bool) -> Result<bool, StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		let previous = account.disabled;
		account.disabled = disabled;
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(previous)
	}

	/// Whether a dynamic account is administratively disabled.
	pub fn is_disabled(&self, name: &str) -> bool {
		self.dynamic
			.read()
			.expect("store lock")
			.iter()
			.find(|account| account.name == name)
			.is_some_and(|account| account.disabled)
	}

	/// Look up a dynamic account by name (case-sensitive). `None` for static
	/// accounts and unknown names.
	pub fn dynamic(&self, name: &str) -> Option<DynamicAccount> {
		self.dynamic
			.read()
			.expect("store lock")
			.iter()
			.find(|account| account.name == name)
			.cloned()
	}

	/// Snapshot every dynamic account (cloned). Used by SCIM's `List` and
	/// other read-only surfaces that need the full set without the lock.
	pub fn dynamic_accounts(&self) -> Vec<DynamicAccount> {
		self.dynamic.read().expect("store lock").clone()
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
		let mut dynamic = self.dynamic.write().expect("store lock");
		let slot = dynamic
			.iter()
			.position(|existing| existing.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		let mut fresh = replacement;
		fresh.name = name.to_string();
		// The collision check on add ignores "self" — we want the same
		// behaviour here, so seed the address map with the existing row.
		let mut known_addresses: Vec<String> = self
			.static_accounts
			.iter()
			.flat_map(|existing| existing.addresses.iter())
			.chain(
				dynamic
					.iter()
					.enumerate()
					.filter(|(index, _)| *index != slot)
					.flat_map(|(_, existing)| existing.addresses.iter()),
			)
			.map(|address| address.to_ascii_lowercase())
			.collect();
		known_addresses.sort();
		for raw in &fresh.addresses {
			if known_addresses
				.binary_search(&raw.to_ascii_lowercase())
				.is_ok()
			{
				return Err(StoreError::Duplicate(raw.clone()));
			}
		}
		dynamic[slot] = fresh;
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	fn persist(&self, dynamic: &[DynamicAccount]) -> Result<(), StoreError> {
		let file = DynamicFile {
			accounts: dynamic.to_vec(),
		};
		let text = toml::to_string_pretty(&file)
			.map_err(|error| StoreError::Invalid(error.to_string()))?;
		crate::storage::write_secret(&self.path, text.as_bytes())?;
		Ok(())
	}

	fn build_directory(&self) -> Directory {
		let dynamic = self.dynamic.read().expect("store lock");
		let sql = self.sql_accounts.read().expect("store lock");
		let ldap = self.ldap_accounts.read().expect("store lock");
		// LDAP accounts are listed first, then SQL, so static config and dynamic
		// accounts chained after take precedence on a name or address collision
		// (the directory's maps keep the last writer): static > dynamic > SQL > LDAP.
		let address_accounts = ldap
			.iter()
			.flat_map(|account| {
				account
					.addresses
					.iter()
					.map(|address| (address.clone(), account.name.clone()))
			})
			.chain(sql.iter().flat_map(|account| {
				account
					.addresses
					.iter()
					.map(|address| (address.clone(), account.name.clone()))
			}))
			.chain(self.static_accounts.iter().flat_map(|account| {
				account
					.addresses
					.iter()
					.map(|address| (address.clone(), account.name.clone()))
			}))
			.chain(dynamic.iter().flat_map(|account| {
				account
					.addresses
					.iter()
					.map(|address| (address.clone(), account.name.clone()))
			}))
			.collect::<Vec<_>>();
		let hashes = sql
			.iter()
			.filter_map(|account| {
				account
					.password_hash
					.as_ref()
					.map(|hash| (account.name.clone(), hash.clone()))
			})
			.chain(self.static_accounts.iter().filter_map(|account| {
				account
					.password_hash
					.as_ref()
					.map(|hash| (account.name.clone(), hash.clone()))
			}))
			.chain(
				dynamic
					.iter()
					.map(|account| (account.name.clone(), account.password_hash.clone())),
			)
			.collect::<Vec<_>>();
		let catch_all = self.static_accounts.iter().flat_map(|account| {
			account
				.catch_all
				.iter()
				.map(|domain| (domain.clone(), account.name.clone()))
		});
		// SCRAM credentials only exist for dynamic accounts (derived from the
		// plaintext password at set time).
		let scram = dynamic.iter().filter_map(|account| {
			account
				.scram
				.clone()
				.map(|stored| (account.name.clone(), stored))
		});
		let totp = dynamic.iter().filter_map(|account| {
			account
				.totp_secret
				.clone()
				.map(|secret| (account.name.clone(), secret))
		});
		// Disabled accounts are passed through to the directory as a name set so
		// `authenticate_local` can reject them before any password work runs.
		// The set rebuilds on every directory swap, mirroring how totp, scram
		// and quotas are wired.
		let disabled = dynamic
			.iter()
			.filter(|account| account.disabled)
			.map(|account| account.name.clone());
		let account_quotas = self.static_accounts.iter().filter_map(|account| {
			account
				.quota_bytes
				.map(|bytes| (account.name.clone(), bytes))
		});
		let forwards = self
			.static_accounts
			.iter()
			.filter(|account| !account.forward.is_empty())
			.map(|account| {
				(
					account.name.clone(),
					(account.forward.clone(), account.forward_keep_local),
				)
			});
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
			.with_aliases(aliases)
			.with_app_passwords(self.app_passwords.iter().cloned())
			.with_ldap(self.ldap_auth.clone())
			.with_masked(masked);
		if let Some(metrics) = self.metrics.clone() {
			dir = dir.with_metrics(metrics);
		}
		dir
	}
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
