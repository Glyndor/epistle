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
		}
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
	/// secret: the last 6 digits of the password are the current TOTP code.
	pub fn authenticate(&self, login: &str, password: &str) -> Option<String> {
		let (account, hash) = self.credentials(login)?;
		let password = match self.totp.get(&account) {
			Some(secret) => {
				let split = password.len().checked_sub(6)?;
				let (pass, code) = password.split_at(split);
				let code: u32 = code.parse().ok()?;
				let bytes = crate::totp::decode_base32_secret(secret)?;
				let now = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.map(|d| d.as_secs())
					.unwrap_or(0);
				if !crate::totp::verify(&bytes, code, now) {
					return None;
				}
				pass
			}
			None => password,
		};
		super::auth::verify_password(hash, password).then_some(account)
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
		self.accounts_by_address
			.get(&address.to_string().to_ascii_lowercase())
			.is_some_and(|owner| owner == account)
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
mod tests {
	use super::*;

	fn directory() -> Directory {
		Directory::new(
			["example.org".to_string()],
			[
				("Alice@EXAMPLE.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		)
	}

	fn parse(raw: &str) -> Address {
		Address::parse(raw).expect("valid address")
	}

	#[test]
	fn quota_resolves_account_then_domain_then_none() {
		let directory = directory()
			.with_account_quotas([("alice".to_string(), 1000)])
			.with_domain_quotas([("example.org".to_string(), 500)]);
		// Account quota wins.
		assert_eq!(directory.quota_for("alice"), Some(1000));
		// bob has no account quota -> the domain default applies.
		assert_eq!(directory.quota_for("bob"), Some(500));
		// Case-insensitive on the account name.
		assert_eq!(directory.quota_for("ALICE"), Some(1000));
		// An unknown account with no hosted address -> no quota.
		assert_eq!(directory.quota_for("nobody"), None);
	}

	#[test]
	fn quota_is_none_without_any_configured() {
		assert_eq!(directory().quota_for("alice"), None);
	}

	#[test]
	fn resolves_known_address_case_insensitively() {
		assert_eq!(
			directory().resolve(&parse("ALICE@example.ORG")),
			Resolution::Account("alice".to_string())
		);
	}

	#[test]
	fn unknown_user_in_local_domain() {
		assert_eq!(
			directory().resolve(&parse("carol@example.org")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn foreign_domain_is_not_local() {
		assert_eq!(
			directory().resolve(&parse("alice@elsewhere.example")),
			Resolution::NotLocal
		);
	}

	#[test]
	fn empty_directory_resolves_nothing() {
		let empty = Directory::default();
		assert_eq!(
			empty.resolve(&parse("alice@example.org")),
			Resolution::NotLocal
		);
	}

	#[test]
	fn subaddressing_resolves_to_base_account() {
		// bob+anything@example.org delivers to bob.
		assert_eq!(
			directory().resolve(&parse("bob+newsletter@example.org")),
			Resolution::Account("bob".to_string())
		);
		// Only the first separator matters; the rest is part of the tag.
		assert_eq!(
			directory().resolve(&parse("Bob+a+b@EXAMPLE.org")),
			Resolution::Account("bob".to_string())
		);
	}

	#[test]
	fn subaddressing_with_unknown_base_is_unknown_user() {
		assert_eq!(
			directory().resolve(&parse("carol+tag@example.org")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn leading_separator_is_not_a_subaddress() {
		assert_eq!(
			directory().resolve(&parse("+tag@example.org")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn subaddressing_can_be_disabled() {
		let directory = directory().with_subaddress_separators([]);
		assert_eq!(
			directory.resolve(&parse("bob+tag@example.org")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn subaddress_separators_are_configurable() {
		let directory = directory().with_subaddress_separators(['-']);
		assert_eq!(
			directory.resolve(&parse("bob-tag@example.org")),
			Resolution::Account("bob".to_string())
		);
		// The default `+` no longer applies once overridden.
		assert_eq!(
			directory.resolve(&parse("bob+tag@example.org")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn catch_all_receives_unknown_local_users() {
		let directory =
			directory().with_catch_all([("example.org".to_string(), "bob".to_string())]);
		// Unknown user falls through to the catch-all account.
		assert_eq!(
			directory.resolve(&parse("nobody@example.org")),
			Resolution::Account("bob".to_string())
		);
		// An explicit address still wins over the catch-all.
		assert_eq!(
			directory.resolve(&parse("alice@example.org")),
			Resolution::Account("alice".to_string())
		);
		// Catch-all never makes a foreign domain local.
		assert_eq!(
			directory.resolve(&parse("nobody@elsewhere.example")),
			Resolution::NotLocal
		);
	}

	#[test]
	fn without_catch_all_unknown_user_is_rejected() {
		assert_eq!(
			directory().resolve(&parse("nobody@example.org")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn domain_alias_resolves_as_target_domain() {
		let directory = directory()
			.with_domain_aliases([("alias.example".to_string(), "example.org".to_string())]);
		assert_eq!(
			directory.resolve(&parse("alice@alias.example")),
			Resolution::Account("alice".to_string())
		);
		// Sub-addressing still applies through the alias.
		assert_eq!(
			directory.resolve(&parse("bob+tag@ALIAS.example")),
			Resolution::Account("bob".to_string())
		);
		// The alias domain is local, so an unknown user is UnknownUser, not NotLocal.
		assert_eq!(
			directory.resolve(&parse("nobody@alias.example")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn unaliased_foreign_domain_is_not_local() {
		assert_eq!(
			directory().resolve(&parse("alice@alias.example")),
			Resolution::NotLocal
		);
	}

	fn directory_with_credentials() -> Directory {
		directory().with_password_hashes([("alice".to_string(), "$argon2id$stub".to_string())])
	}

	#[test]
	fn credentials_by_account_name() {
		let directory = directory_with_credentials();
		let (account, hash) = directory.credentials("ALICE").expect("known account");
		assert_eq!(account, "alice");
		assert_eq!(hash, "$argon2id$stub");
	}

	#[test]
	fn credentials_by_address() {
		let directory = directory_with_credentials();
		let (account, _) = directory
			.credentials("Alice@EXAMPLE.org")
			.expect("known address");
		assert_eq!(account, "alice");
	}

	#[test]
	fn credentials_unknown_login_is_none() {
		let directory = directory_with_credentials();
		assert!(directory.credentials("mallory").is_none());
		assert!(directory.credentials("mallory@example.org").is_none());
		assert!(directory.credentials("alice@elsewhere.example").is_none());
	}

	#[test]
	fn authenticate_enforces_totp_second_factor() {
		let secret = b"12345678901234567890";
		let directory = Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)])
		.with_totp([("alice".to_string(), crate::totp::encode_base32(secret))]);

		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		let code = crate::totp::totp(secret, now);
		// Password followed by the current 6-digit TOTP code.
		let password = format!("secret{code:06}");
		assert_eq!(
			directory.authenticate("alice", &password).as_deref(),
			Some("alice")
		);
		// A wrong code, or the bare password without a code, both fail.
		assert!(directory.authenticate("alice", "secret000000").is_none());
		assert!(directory.authenticate("alice", "secret").is_none());

		// An account without a TOTP secret authenticates with just the password.
		let plain = Directory::new(
			["example.org".to_string()],
			[("bob@example.org".to_string(), "bob".to_string())],
		)
		.with_password_hashes([("bob".to_string(), crate::smtp::auth::tests::hash("pw"))]);
		assert_eq!(plain.authenticate("bob", "pw").as_deref(), Some("bob"));
	}

	#[test]
	fn account_without_hash_cannot_authenticate() {
		// `bob` exists in the address map but has no password hash.
		let directory = directory_with_credentials();
		assert!(directory.credentials("bob@example.org").is_none());
	}
}
