//! The per-account switches for sending and receiving, as the directory
//! holds them.

use super::Directory;

impl Directory {
	/// Attach the accounts whose sending is off and the accounts whose
	/// receiving is off (names, lowercased to match the rest of the
	/// directory). An account in neither list does both, which is the default.
	pub fn with_switches(
		mut self,
		send_off: impl IntoIterator<Item = String>,
		receive_off: impl IntoIterator<Item = String>,
	) -> Self {
		self.send_off = send_off
			.into_iter()
			.map(|name| name.to_ascii_lowercase())
			.collect();
		self.receive_off = receive_off
			.into_iter()
			.map(|name| name.to_ascii_lowercase())
			.collect();
		self
	}

	/// Whether `account` may send mail. Signing in and reading are not part of
	/// it: those follow `disabled` and the protocol allowlist.
	pub fn can_send(&self, account: &str) -> bool {
		!self.send_off.contains(&account.to_ascii_lowercase())
	}

	/// Whether mail addressed to `account` is accepted.
	pub fn receives(&self, account: &str) -> bool {
		!self.receive_off.contains(&account.to_ascii_lowercase())
	}
}
