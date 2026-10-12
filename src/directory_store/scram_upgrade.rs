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
		if !self.scram_enabled {
			return;
		}
		// Derive outside the lock: 600000 PBKDF2 rounds must not stall
		// every other reader of the store.
		let Some(fresh) = ScramStored::with_fresh_salt(password) else {
			return;
		};
		// Take the cross-process `flock`, re-read the file, and only
		// commit the new verifier when the freshly-loaded row is still
		// below the current iteration count. A concurrent login may
		// have already rewritten the row; the first writer wins, the
		// second observes the post-write iteration count and skips
		// silently. The "already upgraded" branch and the "account no
		// longer here" branch both surface as `StoreError::Invalid`,
		// which the caller matches for the silent-skip outcome;
		// `Io` and other real failures fall through to the
		// `tracing::warn` path.
		let result = self.mutate_store(|state| {
			match state
				.accounts
				.iter_mut()
				.find(|existing| existing.name == account)
			{
				Some(row)
					if row
						.scram
						.as_ref()
						.is_some_and(|stored| stored.iterations < SCRAM_ITERATIONS) =>
				{
					row.scram = Some(fresh);
					Ok(())
				}
				_ => Err(super::StoreError::Invalid(
					"scram upgrade: no change".into(),
				)),
			}
		});
		match result {
			Ok(new_state) => self.refresh_after_write(new_state),
			// The "no upgrade needed" path comes back through the
			// sentinel: a concurrent login may already have moved the
			// row to the current iteration count, or the account may
			// have been deleted between the unlock check and the
			// on-disk read. Silently succeed in both cases; nothing to
			// write, nothing to log.
			Err(super::StoreError::Invalid(_)) => {}
			Err(super::StoreError::Io(error)) => {
				tracing::warn!(
					target: "epistle::auth",
					event = "scram.upgrade.failed",
					account = %account,
					error = %error,
					"could not rewrite low-iteration SCRAM verifier"
				);
			}
			Err(other) => {
				tracing::warn!(
					target: "epistle::auth",
					event = "scram.upgrade.failed",
					account = %account,
					error = %other,
					"could not rewrite low-iteration SCRAM verifier"
				);
			}
		}
	}
}

#[cfg(test)]
#[path = "scram_upgrade_tests.rs"]
mod tests;
