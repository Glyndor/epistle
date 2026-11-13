//! Runtime account store and the hot-reloadable directory handle.
//!
//! Static accounts come from the config file and never change at runtime;
//! dynamic accounts live in `<data_dir>/accounts.toml`, managed through the
//! API. The effective directory is rebuilt and swapped on every mutation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::config::Account;
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

mod account;
mod build;
mod builders;
pub use account::DynamicAccount;
mod error;
pub use error::StoreError;
mod handle;
pub use handle::DirectoryHandle;
mod store_debug;

mod forward_catch_all_mutators;
mod mutators;
pub mod scram_upgrade;

mod password_policy_settings;
mod scram_settings;
mod set_totp;
mod switches;
pub use switches::Switch;

/// Watcher that reloads the dynamic stores when a sibling process
/// (the CLI) writes them out of band. See [`file_watcher::FileWatcher`].
pub mod file_watcher;
pub use file_watcher::{ApiKeyReloader, FileWatcher, reload_fingerprint};
/// What the file watcher publishes for the CLI to wait on. See
/// [`reload_status`].
pub mod reload_status;
pub use reload_status::{
	ReloadStatus, ReloadWait, WaitError, read_reload_status, remove_reload_status, wait_for_reload,
};

mod collisions;
pub mod credential_reset;
pub use credential_reset::{CredentialReset, NewPassword, ResetTarget};
pub mod display_name;
mod mutate_store;
mod normalize;
pub use normalize::account_name;

/// Hook the directory calls back into when a cleartext authentication
/// succeeds against a dynamic account whose stored SCRAM verifier is below
/// the current iteration constant. See [`crate::directory_store::scram_upgrade`]
/// for the trait + no-op default + store impl; this file only re-exports
/// them so `mod.rs` stays under the per-file code-line budget.
pub use crate::directory_store::scram_upgrade::{NoopScramUpgrader, ScramUpgrader};

#[derive(Debug, Default, Serialize, Deserialize)]
struct DynamicFile {
	#[serde(default)]
	accounts: Vec<DynamicAccount>,
}

/// The mutable account store: static accounts + persisted dynamic ones.
pub struct AccountStore {
	path: PathBuf,
	domains: Vec<String>,
	domain_aliases: std::collections::HashMap<String, String>,
	/// Hosted domains switched off (`disabled_domains` in the configuration).
	disabled_domains: Vec<String>,
	/// Hosted domains that only receive (`receive_only_domains`).
	send_off_domains: Vec<String>,
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
	/// At-rest encryption for the TOTP secret (see
	/// `src/directory_store/set_totp/mod.rs`).
	crypto: crate::storage::MessageCrypto,
	handle: DirectoryHandle,
}

impl AccountStore {
	/// The hot-reloadable handle shared with servers and delivery.
	pub fn handle(&self) -> DirectoryHandle {
		self.handle.clone()
	}

	/// The absolute path of the on-disk accounts file the store
	/// mutates. The CLI uses it to know which file to wait on after
	/// a mutator returns.
	pub fn store_path(&self) -> &Path {
		&self.path
	}

	/// The checks `add` runs that do not depend on the accounts already
	/// on disk: a valid name, at least one address, and every address
	/// in a configured domain. The CLI calls this before it reads the
	/// password, so nobody types one for a name or address that cannot
	/// be created. The input is normalized the way `add` normalizes it,
	/// so both refuse the same input with the same error; the checks
	/// against existing accounts still run inside [`AccountStore::add`]
	/// under the lock.
	pub fn validate_for_add(&self, name: &str, addresses: &[String]) -> Result<(), StoreError> {
		let mut account = DynamicAccount {
			name: normalize::account_name(name),
			addresses: addresses.to_vec(),
			..DynamicAccount::default()
		};
		normalize::account(&mut account);
		self.check_name_and_addresses(&account)
	}

	/// The part of [`AccountStore::validate_for_add`] that `add` repeats
	/// under the lock.
	fn check_name_and_addresses(&self, account: &DynamicAccount) -> Result<(), StoreError> {
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
		Ok(())
	}

	/// Add a dynamic account. `password_hash` must already be argon2id.
	pub fn add(&self, mut account: DynamicAccount) -> Result<(), StoreError> {
		account.name = normalize::account_name(&account.name);
		normalize::account(&mut account);
		account.display_name = display_name::stored(account.display_name.as_deref())?;
		self.mutate_store(|state| {
			self.check_name_and_addresses(&account)?;
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
	/// dynamic account carries `name`. An address the account does not
	/// already hold gets the checks `add` runs: `Invalid` outside the
	/// served domains, `Duplicate` when another account, a static alias or
	/// a masked address already routes it. The password, the SCRAM verifier,
	/// the TOTP secret and a pending reset are the stored ones, whatever
	/// `replacement` holds; `new_password` replaces the password in the same
	/// write.
	pub fn replace_account(
		&self,
		name: &str,
		replacement: DynamicAccount,
		new_password: Option<NewPassword>,
	) -> Result<(), StoreError> {
		self.mutate_store(|state| {
			let slot = state
				.accounts
				.iter()
				.position(|existing| existing.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			let mut fresh = replacement;
			fresh.name = name.to_string();
			credential_reset::carry(&state.accounts[slot], &mut fresh, new_password);
			normalize::account(&mut fresh);
			fresh.display_name = display_name::stored(fresh.display_name.as_deref())?;
			// The same checks `add` runs, except for an address the account
			// already holds: a replacement that keeps it is not claiming it.
			let held: Vec<String> = state.accounts[slot]
				.addresses
				.iter()
				.map(|own| crate::util::address::normalize(own))
				.collect();
			let mut claimed = fresh.clone();
			claimed.addresses.retain(|raw| !held.contains(raw));
			if fresh.addresses.is_empty() || !claimed.addresses.is_empty() {
				self.check_name_and_addresses(&claimed)?;
			}
			for raw in &claimed.addresses {
				if self.address_taken(&state.accounts, Some(name), raw) {
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
		let (send_off, receive_off) = build::switches_off(&self.static_accounts, &dynamic);
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
			.with_disabled_domains(self.disabled_domains.iter().cloned())
			.with_send_off_domains(self.send_off_domains.iter().cloned())
			.with_scram(scram)
			.with_totp(totp)
			.with_disabled(disabled)
			.with_credential_reset(credential_reset::names(&dynamic))
			.with_switches(send_off, receive_off)
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
			.with_masked_paused(self.masked.read().expect("masked lock").paused())
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

#[cfg(test)]
mod tests;
