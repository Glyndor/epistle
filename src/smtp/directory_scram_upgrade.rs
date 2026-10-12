//! SCRAM-upgrader attachment for [`super::Directory`].
//!
//! The directory owns the `scram_upgrader` field, the
//! `with_scram_upgrader` builder, and the per-attempt
//! `maybe_upgrade_scram` call site. The block is split into a sibling
//! so `directory.rs` stays under the per-file code-line budget.

impl super::Directory {
	/// Attach the callback invoked to refresh a dynamic account's SCRAM
	/// verifier on a successful cleartext authentication. Used by the
	/// store to make every rebuilt directory point at the live store, so
	/// the directory can rewrite the verifier when its stored iteration
	/// count is below the current constant without taking a back-reference
	/// to the store.
	pub fn with_scram_upgrader(
		mut self,
		upgrader: std::sync::Arc<dyn crate::directory_store::ScramUpgrader>,
	) -> Self {
		self.scram_upgrader = Some(upgrader);
		self
	}

	/// Refresh the dynamic account's verifier when its stored iteration
	/// count is below the current SCRAM constant. Static and SQL accounts
	/// are skipped — the upgrade only runs for accounts whose SCRAM row
	/// the store owns. The check is a single hash lookup; the upgrade is
	/// best-effort and a failure here does not change the wire response,
	/// which already returned `Some(account)` above.
	pub(super) fn maybe_upgrade_scram(&self, account: &str, password: &str) {
		let Some(upgrader) = self.scram_upgrader.as_ref() else {
			return;
		};
		let needs = match self.scram.get(&account.to_ascii_lowercase()) {
			Some(stored) => stored.iterations < crate::smtp::scram::SCRAM_ITERATIONS,
			// No verifier at all: SCRAM is off, or the account never had one.
			// `authenticate_with_ip` is the only place this is consulted, and
			// a SCRAM-less account is exactly what `scram = false` wants, so
			// the upgrade is a no-op rather than a missing-row upgrade.
			None => return,
		};
		if !needs {
			return;
		}
		if let Some(fresh) = crate::smtp::scram::ScramStored::with_fresh_salt(password) {
			upgrader.upgrade(account, fresh);
		}
	}
}