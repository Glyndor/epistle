//! The per-account switches for sending and receiving mail.
//!
//! Two independent settings, both on by default: `send` (the account may
//! submit mail) and `receive` (mail addressed to the account is accepted).
//! They are independent of `disabled` (sign-in) and of `allowed_protocols`
//! (which protocols may sign in). A dynamic account keeps them in
//! `accounts.toml`; a static one carries `send` and `receive` keys in the
//! configuration file.

use super::{AccountStore, StoreError};

/// Which of the two switches a mutation or a read names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switch {
	/// Whether the account may send mail.
	Send,
	/// Whether mail addressed to the account is accepted.
	Receive,
}

impl AccountStore {
	/// Turn one switch of a dynamic account on or off and return the state it
	/// had. On clears the field rather than writing `true`, so a file whose
	/// accounts never used the switches stays byte for byte what it was.
	/// `NotFound` for static and unknown accounts.
	pub fn set_switch(&self, name: &str, switch: Switch, on: bool) -> Result<bool, StoreError> {
		let mut previous = true;
		self.mutate_store(|state| {
			let target = state
				.accounts
				.iter_mut()
				.find(|account| account.name == name)
				.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
			let field = match switch {
				Switch::Send => &mut target.send,
				Switch::Receive => &mut target.receive,
			};
			previous = field.unwrap_or(true);
			*field = (!on).then_some(false);
			Ok(())
		})?;
		Ok(previous)
	}

	/// Whether `name` may send mail and whether it receives it, as
	/// `(send, receive)`, for a static or a dynamic account. An unknown name
	/// reads as `(true, true)`, the default.
	pub fn switches(&self, name: &str) -> (bool, bool) {
		if let Some(account) = self.dynamic(name) {
			return (
				account.send.unwrap_or(true),
				account.receive.unwrap_or(true),
			);
		}
		match self.static_view(name) {
			Some(account) => (
				account.send.unwrap_or(true),
				account.receive.unwrap_or(true),
			),
			None => (true, true),
		}
	}
}
