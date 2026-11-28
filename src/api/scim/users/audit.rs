//! The audit lines of the credential changes SCIM makes.
//!
//! A SCIM write lands on the same account store the management API uses, so
//! it has to leave the same trace: a password it sets is an
//! `account.password_reset` — the event the management route that sets a
//! password writes — and an account it suspends or enables again is an
//! `account.disabled` or an `account.enabled`, the events the management
//! route that suspends and resumes an account writes. An identity provider
//! that provisions accounts therefore leaves the same trace as an operator
//! at a terminal.
//!
//! The lines are written on the task that made the change, right after the
//! write and with no await in between, so a client that drops the
//! connection after the change cannot take the trace with it.
//!
//! What is never written: the password, its hash, the SCRAM credentials and
//! the bearer. The line says that a credential changed and for which
//! account, and nothing about the credential itself.

use std::net::IpAddr;

use crate::api::audit::{self, AuditEvent, SuspensionEvent};

/// The credential changes one SCIM write made.
///
/// A write that changed nothing (a `PATCH` that asks for the `active` flag
/// the account already has) holds no change and writes no line.
pub(super) struct Changes {
	/// The account the change was about.
	name: String,
	/// The password was replaced.
	password: bool,
	/// The account's `active` flag changed to this value.
	active: Option<bool>,
	/// The label of the key that asked (never the key).
	key: Option<String>,
	/// The address the change came from.
	client_ip: Option<IpAddr>,
}

impl Changes {
	/// The changes of a write about `name`, made by the key `key`.
	pub(super) fn new(name: &str, key: Option<&str>, client_ip: Option<IpAddr>) -> Self {
		Self {
			name: name.to_string(),
			password: false,
			active: None,
			key: key.map(str::to_owned),
			client_ip,
		}
	}

	/// The write replaced the password of the account.
	pub(super) fn password(&mut self) {
		self.password = true;
	}

	/// The write changed the account's `active` flag to `active`.
	pub(super) fn active(&mut self, active: bool) {
		self.active = Some(active);
	}

	/// The write found the account disabled as `found` says and left it as
	/// `left` says: a change only when the two differ. Both come from the
	/// write itself, not from a read made before it.
	pub(super) fn state(&mut self, found: bool, left: bool) {
		if found != left {
			self.active(!left);
		}
	}

	/// Write the line of every change the write made. A write that changed
	/// nothing writes none.
	pub(super) fn write(&self) {
		if self.password {
			// The label of the key that asked goes on the line: a credential
			// change is told from the others by the key that made it.
			audit::log_privilege_change_by_key(
				AuditEvent::PasswordReset,
				&self.name,
				self.key.as_deref(),
				self.client_ip,
			);
		}
		if let Some(active) = self.active {
			let event = if active {
				SuspensionEvent::Enabled
			} else {
				SuspensionEvent::Disabled
			};
			audit::log_suspension_change(event, &self.name, self.key.as_deref(), self.client_ip);
		}
	}
}
