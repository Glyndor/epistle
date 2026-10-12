//! SCRAM wiring on [`super::AccountStore`].
//!
//! The `with_scram_upgrader` / `install_scram_upgrader` pair and the
//! `with_scram_enabled` / `scram_enabled` pair live here so
//! [`super::AccountStore`] in `mod.rs` stays under the per-file code-line
//! budget. The upgrader lets the directory call back into the store when
//! a cleartext authentication succeeds against a low-iteration dynamic
//! verifier; the enabled flag drives the account-create and password-change
//! paths: when `false`, the SCRAM verifier is omitted from
//! `DynamicAccount::with_password`, and a password-change call that
//! passes `None` for the verifier drops the existing row.

use std::sync::Arc;

use super::ScramUpgrader;

impl super::AccountStore {
	/// Replace the SCRAM upgrader the rebuilt directories call when a
	/// cleartext authentication succeeds against a low-iteration dynamic
	/// verifier. The `serve` builder wires `Arc<Self>` so the directory's
	/// upgrade writes round-trip to the on-disk account row.
	pub fn with_scram_upgrader(mut self, upgrader: Arc<dyn ScramUpgrader>) -> Self {
		self.scram_upgrader = upgrader;
		self.handle.replace(self.build_directory());
		self
	}

	/// Install the live upgrader on a `Arc<AccountStore>` that has
	/// exactly one strong reference (the `serve` builder). Used once at
	/// startup to wire the directory back to the store; subsequent
	/// mutators go through the `Arc<dyn ScramUpgrader>` itself, which
	/// holds a stable reference.
	pub(crate) fn install_scram_upgrader(&mut self, upgrader: Arc<dyn ScramUpgrader>) {
		self.scram_upgrader = upgrader;
		self.handle.replace(self.build_directory());
	}

	/// Toggle whether new dynamic accounts get a SCRAM verifier derived
	/// and whether the next password change drops an existing one. Wired
	/// from the `[auth] scram` config key at startup.
	pub fn with_scram_enabled(mut self, enabled: bool) -> Self {
		self.scram_enabled = enabled;
		self
	}

	/// Whether new dynamic accounts should derive a SCRAM verifier.
	pub fn scram_enabled(&self) -> bool {
		self.scram_enabled
	}
}
