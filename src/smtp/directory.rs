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
		}
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
		if !self.domains.contains(address.domain()) {
			return Resolution::NotLocal;
		}
		if let Some(account) = self
			.accounts_by_address
			.get(&address.to_string().to_ascii_lowercase())
		{
			return Resolution::Account(account.clone());
		}
		// Sub-addressing: strip the tag and retry the base address.
		if let Some(base) = self.strip_subaddress(address)
			&& let Some(account) = self.accounts_by_address.get(&base)
		{
			return Resolution::Account(account.clone());
		}
		Resolution::UnknownUser
	}

	/// The base `local@domain` key (lowercased) once the earliest sub-address
	/// separator and everything after it are removed, or `None` if the
	/// address carries no tag.
	fn strip_subaddress(&self, address: &Address) -> Option<String> {
		let local = address.local_part();
		let cut = self
			.subaddress_separators
			.iter()
			.filter_map(|sep| local.find(*sep))
			.min()?;
		// A leading separator (e.g. `+tag`) leaves no base local-part.
		if cut == 0 {
			return None;
		}
		Some(format!("{}@{}", &local[..cut], address.domain()).to_ascii_lowercase())
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
	fn account_without_hash_cannot_authenticate() {
		// `bob` exists in the address map but has no password hash.
		let directory = directory_with_credentials();
		assert!(directory.credentials("bob@example.org").is_none());
	}
}
