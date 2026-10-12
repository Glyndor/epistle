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

/// Hook the directory calls back into when a cleartext authentication
/// succeeds against a dynamic account whose stored SCRAM verifier is below
/// the current iteration constant. The store owns the on-disk row, so the
/// directory carries the upgrader as an opaque trait object instead of a
/// back-reference to the store itself. `Debug` keeps the `Directory`
/// derive happy (the `scram_upgrader` field is part of the directory's
/// debug output).
pub trait ScramUpgrader: std::fmt::Debug + Send + Sync {
	/// Replace the stored verifier for `account` with `fresh`. Errors are
	/// swallowed by the caller: a write failure must not change the
	/// authentication outcome that triggered the upgrade.
	fn upgrade(&self, account: &str, fresh: crate::smtp::scram::ScramStored);
}

/// The default upgrader: no upgrade until the `serve` builder wires an
/// `Arc<AccountStore>` in via [`super::AccountStore::with_scram_upgrader`].
/// Keeps the `Directory::authenticate_with_ip` path safe in unit tests and
/// CLI callers that build a store without ever opening a live runtime.
#[derive(Debug, Clone, Copy)]
pub struct NoopScramUpgrader;

impl ScramUpgrader for NoopScramUpgrader {
	fn upgrade(&self, _account: &str, _fresh: crate::smtp::scram::ScramStored) {}
}

/// The directory calls back into the store through this trait when a
/// dynamic account's stored SCRAM verifier is below the current iteration
/// constant after a successful cleartext authentication. Kept here next
/// to the trait definition so the upgrade path stays in one file.
impl super::ScramUpgrader for super::AccountStore {
	fn upgrade(&self, account: &str, fresh: crate::smtp::scram::ScramStored) {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let Some(row) = dynamic.iter_mut().find(|existing| existing.name == account) else {
			return;
		};
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
}