//! SCRAM-upgrader attachment for [`super::Directory`].
//!
//! The directory owns the `scram_upgrader` field, the
//! `with_scram_upgrader` builder, and the per-attempt
//! `maybe_upgrade_scram` call site. The block is split into a sibling
//! so `directory.rs` stays under the per-file code-line budget.

use crate::password::Policy;

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

	/// Hand the password that just authenticated to the upgrader when the
	/// account's stored verifier is below the current SCRAM iteration
	/// count. Only dynamic accounts carry a verifier, so static and SQL
	/// accounts never reach the upgrader. The check is a single map
	/// lookup; the upgrade is best-effort and cannot change the wire
	/// response, which is already `Some(account)`.
	pub(super) fn maybe_upgrade_scram(&self, account: &str, password: &str) {
		let Some(upgrader) = self.scram_upgrader.as_ref() else {
			return;
		};
		let below_current = self
			.scram
			.get(&account.to_ascii_lowercase())
			.is_some_and(|stored| stored.iterations < crate::smtp::scram::SCRAM_ITERATIONS);
		if below_current {
			upgrader.upgrade(account, password);
		}
	}

	/// Whether the runtime password policy on this directory is unicode
	/// (so set-time and verify-time normalise via NFKC). The
	/// `upgrade_scram` callback does not see the directory directly; the
	/// store forwards its own policy in for it. Currently unused by the
	/// directory itself — the policy is read by `authenticate_local` and
	/// the app-password admission path — but the accessor lets the
	/// `upgrade_scram` wiring stay decoupled from the store's internal
	/// state, and is exercised by the storage-layer tests that build a
	/// directory in isolation.
	#[allow(dead_code)]
	pub(super) fn password_policy(&self) -> Policy {
		self.password_policy
	}
}
