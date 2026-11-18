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

	/// Mark the accounts whose credentials were reset and are not yet
	/// replaced. Like a disabled account, such an account keeps its mail and
	/// signs in nowhere; names are lowercased for the same reason.
	pub fn with_credential_reset(mut self, names: impl IntoIterator<Item = String>) -> Self {
		self.credential_reset = names.into_iter().map(|n| n.to_ascii_lowercase()).collect();
		self
	}

	/// Whether `account` waits for the credentials a reset asked for.
	pub fn awaits_credential_reset(&self, account: &str) -> bool {
		self.credential_reset
			.contains(&account.to_ascii_lowercase())
	}

	/// Whether `account` may act at all: it is not administratively disabled
	/// and does not wait for a credential reset. Sign-in refuses an account
	/// for which this is `false` ([`Directory::admit_login`]), and a session
	/// that signed in before the change asks again before each command, so
	/// disabling or resetting an account also ends the sessions it has open.
	pub fn account_is_live(&self, account: &str) -> bool {
		let account = account.to_ascii_lowercase();
		!self.disabled.contains(&account) && !self.credential_reset.contains(&account)
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
