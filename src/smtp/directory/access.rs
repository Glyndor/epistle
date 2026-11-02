//! Which accounts are switched off and which protocols an account may use.

use std::collections::HashSet;

use super::Directory;

impl Directory {
	/// Mark a set of accounts as administratively disabled. While disabled,
	/// the account still owns its mailboxes and is visible to management
	/// tooling, but authentication rejects every password attempt before any
	/// hashing. Names are lowercased so the check matches `credentials()`
	/// (which also lowercases the bare-login path).
	pub fn with_disabled(mut self, names: impl IntoIterator<Item = String>) -> Self {
		self.disabled = names.into_iter().map(|n| n.to_ascii_lowercase()).collect();
		self
	}

	/// Whether `account` is administratively disabled.
	pub fn is_disabled(&self, account: &str) -> bool {
		self.disabled.contains(&account.to_ascii_lowercase())
	}

	/// Attach the per-account protocol allowlist (account name → set of
	/// protocols the account may authenticate through). Account names are
	/// lowercased to match `credentials()`. An absent entry is
	/// "every protocol authenticates" (the default for accounts that never
	/// opted into the restriction); an empty set is "no protocol
	/// authenticates" — the account owns its mailboxes but cannot sign in
	/// anywhere.
	pub fn with_allowed_protocols(
		mut self,
		entries: impl IntoIterator<Item = (String, Vec<crate::config::Protocol>)>,
	) -> Self {
		self.allowed_protocols = entries
			.into_iter()
			.map(|(name, protocols)| {
				(
					name.to_ascii_lowercase(),
					protocols.into_iter().collect::<HashSet<_>>(),
				)
			})
			.collect();
		self
	}

	/// Whether `account` may authenticate through `protocol`. `None` when
	/// the account carries no allowlist (every protocol is admitted); a
	/// stored set decides otherwise.
	pub fn is_protocol_allowed(&self, account: &str, protocol: crate::config::Protocol) -> bool {
		self.allowed_protocols
			.get(&account.to_ascii_lowercase())
			.is_none_or(|set| set.contains(&protocol))
	}
}
