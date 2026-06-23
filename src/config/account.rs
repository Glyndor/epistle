//! Account definitions: who receives mail at which addresses.

use serde::Deserialize;

/// One mail account.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
	/// Account name; doubles as the mailbox directory name.
	pub name: String,
	/// Addresses delivered to this account.
	pub addresses: Vec<String>,
	/// argon2id password hash (PHC string). Without it the account is
	/// receive-only and cannot authenticate.
	pub password_hash: Option<String>,
	/// Domains for which this account receives mail addressed to otherwise
	/// unknown local users (catch-all). Off by default.
	#[serde(default)]
	pub catch_all: Vec<String>,
	/// Storage quota in bytes for this account. Absent falls back to the
	/// domain quota, then the server default.
	#[serde(default)]
	pub quota_bytes: Option<u64>,
	/// External addresses this account's mail is also forwarded to. Empty
	/// (the default) disables forwarding.
	#[serde(default)]
	pub forward: Vec<String>,
	/// Keep the local copy when forwarding. True (the default) is safe: mail
	/// is never lost. Set false for pure forwarding (no local mailbox copy).
	#[serde(default = "default_true")]
	pub forward_keep_local: bool,
}

/// Serde default for boolean fields that default to true.
fn default_true() -> bool {
	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_account() {
		let account: Account = toml::from_str(
			r#"
name = "alice"
addresses = ["alice@example.org", "postmaster@example.org"]
"#,
		)
		.expect("parse account");
		assert_eq!(account.name, "alice");
		assert_eq!(account.addresses.len(), 2);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Account, _> = toml::from_str(
			r#"
name = "alice"
addresses = []
quota = "1G"
"#,
		);
		assert!(result.is_err());
	}
}
