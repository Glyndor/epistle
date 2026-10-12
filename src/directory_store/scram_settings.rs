//! SCRAM wiring on [`super::AccountStore`].
//!
//! The `with_scram_upgrader` / `into_shared` pair and the
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
	/// verifier. Tests inject a double here; `serve` goes through
	/// [`Self::into_shared`], which wires the store itself.
	pub fn with_scram_upgrader(mut self, upgrader: Arc<dyn ScramUpgrader>) -> Self {
		self.scram_upgrader = upgrader;
		self.handle.replace(self.build_directory());
		self
	}

	/// Share the store and wire it as its own SCRAM upgrader, so the
	/// directories it builds can rewrite a low-iteration verifier after a
	/// successful cleartext login. This is how `serve` builds its store.
	pub fn into_shared(mut self) -> Arc<Self> {
		Arc::new_cyclic(|weak| {
			self.scram_upgrader = Arc::new(super::scram_upgrade::StoreUpgrader(weak.clone()));
			self.handle.replace(self.build_directory());
			self
		})
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
