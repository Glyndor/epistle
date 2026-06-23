//! Recipient resolution: which account, if any, receives an address.

use std::collections::{HashMap, HashSet};

use super::address::Address;

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
	/// Storage quota (bytes) per account name; absent falls back to the domain
	/// quota, then the server default.
	account_quotas: HashMap<String, u64>,
	/// Default storage quota (bytes) per domain, applied to accounts in that
	/// domain without their own quota.
	domain_quotas: HashMap<String, u64>,
	/// Per-account external forwarding: `(targets, keep_local)`. Mail for the
	/// account is also queued to each target; `keep_local` keeps the local copy.
	forwards: HashMap<String, (Vec<String>, bool)>,
	/// Multi-target aliases, keyed by lowercased alias address.
	aliases: HashMap<String, AliasSpec>,
	/// Secondary app passwords per account name. Each entry is tried when the
	/// primary password check fails (see [`Directory::authenticate_with_ip`]).
	app_passwords: HashMap<String, Vec<crate::directory_store::AppPassword>>,
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
			account_quotas: HashMap::new(),
			domain_quotas: HashMap::new(),
			forwards: HashMap::new(),
			aliases: HashMap::new(),
			app_passwords: HashMap::new(),
		}
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

	/// Verify a login with its password, enforcing TOTP when the account has a
	/// secret: the last 6 digits of the password are the current TOTP code. This
	/// is a thin wrapper over [`Directory::authenticate_with_ip`] for callers
	/// without a client IP (app-password CIDR allowlists then never match).
	pub fn authenticate(&self, login: &str, password: &str) -> Option<String> {
		self.authenticate_with_ip(login, password, None)
	}

	/// Verify a login, falling back to the account's app passwords when the
	/// primary password fails. `ip` is the client address used to enforce an app
	/// password's CIDR allowlist (an allowlisted app password is unusable
	/// without it).
	///
	/// Fail-closed and no user-enumeration oracle: an unknown login returns
	/// `None` from [`Directory::credentials`] before any hashing, exactly as a
	/// known account whose primary and every app password mismatch — both end in
	/// `None`. The app-password fallback runs only for a resolved account, so it
	/// does not change the unknown-vs-known timing class.
	pub fn authenticate_with_ip(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
	) -> Option<String> {
		let (account, hash) = self.credentials(login)?;
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
		let split = password.len().checked_sub(6)?;
		let (pass, code) = password.split_at(split);
		let code: u32 = code.parse().ok()?;
		let bytes = crate::totp::decode_base32_secret(secret)?;
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		crate::totp::verify(&bytes, code, now).then_some(pass)
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
