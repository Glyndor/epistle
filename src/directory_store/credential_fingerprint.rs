//! A digest of the credentials an account holds now, so a grant that outlives
//! a sign-in (an OAuth refresh token) can tell that the password or the second
//! factor changed since it was issued.

use super::AccountStore;
use super::credential_reset::hash_digest;

impl AccountStore {
	/// A digest of the password hash of `name` and, for a dynamic account, of
	/// its second-factor secret, or `None` when no record holds a credential
	/// marker: a receive-only account, one that does not exist, and an account
	/// of the LDAP directory, whose password lives outside epistle and leaves no
	/// marker here. Callers treat `None` as "cannot tell" and refuse to rely on
	/// the account staying unchanged. The digest changes whenever the password
	/// is changed or reset or the second factor is set, replaced or removed,
	/// and never reveals either. Records are looked up in the dynamic, static
	/// and SQL stores in that order; the SQL and static accounts carry no
	/// second factor here.
	pub fn credential_fingerprint(&self, name: &str) -> Option<String> {
		let dynamic = self.dynamic.read().expect("store lock");
		if let Some(account) = dynamic.iter().find(|account| account.name == name) {
			let marker = format!(
				"{}\0{}",
				account.password_hash,
				account.totp_secret.as_deref().unwrap_or("")
			);
			return Some(hash_digest(&marker));
		}
		drop(dynamic);
		if let Some(account) = self
			.static_accounts
			.iter()
			.find(|account| account.name == name)
		{
			return account.password_hash.as_deref().map(hash_digest);
		}
		let sql = self.sql_accounts.read().expect("store lock");
		if let Some(account) = sql.iter().find(|account| account.name == name) {
			return account.password_hash.as_deref().map(hash_digest);
		}
		None
	}
}
