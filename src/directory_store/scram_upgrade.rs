//! SCRAM verifier upgrade hook.
//!
//! The directory calls back through [`ScramUpgrader`] after a cleartext
//! authentication succeeds against a dynamic account whose stored
//! verifier was derived with fewer than the current iteration
//! constant. The trait lives here so [`super::AccountStore`] can
//! implement it without bloating `mod.rs` past the per-file
//! code-line budget; `mod.rs` only re-exports the two names so
//! `super::Directory::with_scram_upgrader` and the tests can keep
//! referring to them.

use std::sync::Weak;

use crate::smtp::scram::{SCRAM_ITERATIONS, ScramStored};

/// Hook the directory calls back into when a cleartext authentication
/// succeeds against a dynamic account whose stored SCRAM verifier is below
/// the current iteration constant. The store owns the on-disk row, so the
/// directory carries the upgrader as an opaque trait object instead of a
/// back-reference to the store itself. `Debug` keeps the `Directory`
/// derive happy (the `scram_upgrader` field is part of the directory's
/// debug output).
pub trait ScramUpgrader: std::fmt::Debug + Send + Sync {
	/// Re-derive `account`'s verifier from the `password` that just
	/// authenticated. The implementor decides whether a rewrite is due and
	/// pays the PBKDF2 cost only then. Errors are swallowed: a write failure
	/// must not change the authentication outcome that triggered it.
	fn upgrade(&self, account: &str, password: &str);
}

/// The default upgrader: no upgrade until the store is shared through
/// [`super::AccountStore::into_shared`]. Keeps the
/// `Directory::authenticate_with_ip` path write-free in unit tests and CLI
/// callers that build a store without ever opening a live runtime.
#[derive(Debug, Clone, Copy)]
pub struct NoopScramUpgrader;

impl ScramUpgrader for NoopScramUpgrader {
	fn upgrade(&self, _account: &str, _password: &str) {}
}

/// The upgrader [`super::AccountStore::into_shared`] wires into the
/// directories the store builds. The reference is weak because the store
/// owns those directories: a strong one would be a cycle that keeps the
/// store alive forever.
#[derive(Debug)]
pub(super) struct StoreUpgrader(pub(super) Weak<super::AccountStore>);

impl ScramUpgrader for StoreUpgrader {
	fn upgrade(&self, account: &str, password: &str) {
		if let Some(store) = self.0.upgrade() {
			store.upgrade_scram(account, password);
		}
	}
}

impl super::AccountStore {
	/// Replace `account`'s verifier with one derived at the current
	/// iteration count under a fresh salt, when SCRAM is enabled and the
	/// stored verifier is below that count. An account without a verifier
	/// is left without one.
	pub(super) fn upgrade_scram(&self, account: &str, password: &str) {
		if !self.scram_enabled || !self.needs_scram_upgrade(account) {
			return;
		}
		// Derive outside the lock: 600000 PBKDF2 rounds must not stall
		// every other reader of the store.
		let Some(fresh) = ScramStored::with_fresh_salt(password) else {
			return;
		};
		let mut dynamic = self.dynamic.write().expect("store lock");
		let Some(row) = dynamic.iter_mut().find(|existing| existing.name == account) else {
			return;
		};
		// A concurrent login may have rewritten the row while this one
		// derived; keep the first rewrite instead of churning the salt.
		if !row
			.scram
			.as_ref()
			.is_some_and(|stored| stored.iterations < SCRAM_ITERATIONS)
		{
			return;
		}
		row.scram = Some(fresh);
		if let Err(error) = self.persist(&dynamic) {
			tracing::warn!(
				target: "epistle::auth",
				event = "scram.upgrade.failed",
				account = %account,
				error = %error,
				"could not rewrite low-iteration SCRAM verifier"
			);
			return;
		}
		drop(dynamic);
		self.handle.replace(self.build_directory());
	}

	fn needs_scram_upgrade(&self, account: &str) -> bool {
		self.dynamic
			.read()
			.expect("store lock")
			.iter()
			.find(|existing| existing.name == account)
			.and_then(|row| row.scram.as_ref())
			.is_some_and(|stored| stored.iterations < SCRAM_ITERATIONS)
	}
}

#[cfg(test)]
#[path = "scram_upgrade_tests.rs"]
mod tests;
