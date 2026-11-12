//! Builder-style setters that attach configuration to a freshly opened
//! [`AccountStore`] and rebuild its directory.

use std::path::Path;
use std::sync::{Arc, RwLock};

use super::{
	Account, AccountStore, AliasStore, AppPasswordStore, DirectoryHandle, DynamicFile, LdapAccount,
	LdapAuthenticator, MaskedAddressStore, NoopScramUpgrader, Policy, ScramUpgrader, SqlAccount,
	StoreError, normalize, with_safe_names,
};

use crate::smtp::directory::Directory;

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
			disabled_domains: Vec::new(),
			send_off_domains: Vec::new(),
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

	/// Switch off hosted domains and rebuild the directory.
	pub fn with_disabled_domains(mut self, domains: Vec<String>) -> Self {
		self.disabled_domains = domains;
		self.handle.replace(self.build_directory());
		self
	}

	/// Set the hosted domains nobody may send as (`receive_only_domains`)
	/// and rebuild the directory.
	pub fn with_send_off_domains(mut self, domains: Vec<String>) -> Self {
		self.send_off_domains = domains;
		self.handle.replace(self.build_directory());
		self
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
}
