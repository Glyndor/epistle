//! Rewriting a password hash at a higher argon2id cost after a sign-in.
//!
//! The directory calls [`super::ScramUpgrader::rehash_password`] when a
//! password verified against a hash that is weaker than the cost in force
//! (`[auth] argon2_*`, see [`crate::smtp::auth::cost`]). The store writes the
//! new hash under the same cross-process lock and atomic write a password
//! change uses, and only when the row still holds the hash that verified: a
//! password changed in the meantime is never put back, and two sign-ins at
//! once write once.
//!
//! The write is best-effort. A hash that cannot be written leaves the old one
//! in place and the sign-in succeeds; the next one tries again.
//!
//! A grant bound to the credentials (an OAuth refresh token) carries a digest
//! of the password hash. The password did not change, so the digest must not:
//! [`Rehashed`] keeps the digest the account had, for as long as the hash and
//! the second factor are the ones it was made for.

use serde::{Deserialize, Serialize};

use super::credential_reset::hash_digest;
use super::{AccountStore, DynamicAccount, StoreError};

/// The credential digest an account had before its hash was rewritten, and
/// what it was made for. Written only by the rewrite; every other change of
/// the password or the second factor makes it stale, and a stale one is
/// ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rehashed {
	/// Digest of the rewritten password hash this marker belongs to.
	hash: String,
	/// Digest of the second-factor secret it belongs to; of nothing when
	/// the account has none.
	second_factor: String,
	/// The credential digest to keep reporting.
	fingerprint: String,
	/// Digest of the password hash the account held before its first
	/// rewrite: what a reset decided earlier still names.
	origin: String,
}

fn marker(password_hash: &str, totp_secret: Option<&str>) -> String {
	format!("{password_hash}\0{}", totp_secret.unwrap_or(""))
}

impl Rehashed {
	/// Whether this marker was made for the credentials `account` holds.
	fn holds_for(&self, account: &DynamicAccount) -> bool {
		self.hash == hash_digest(&account.password_hash)
			&& self.second_factor == hash_digest(account.totp_secret.as_deref().unwrap_or(""))
	}
}

impl DynamicAccount {
	/// Whether the account holds the password hash whose digest is
	/// `digest`: the hash it holds now, or the one a rewrite replaced. A
	/// reset of credentials decided before the rewrite names that one, and
	/// the rewrite must not let it slip.
	pub fn holds_hash_digest(&self, digest: &str) -> bool {
		hash_digest(&self.password_hash) == digest
			|| self
				.rehashed
				.as_ref()
				.is_some_and(|kept| kept.holds_for(self) && kept.origin == digest)
	}
}

/// The digest of the credentials `account` holds: of its password hash and
/// second factor, or the one it had before a rewrite of the hash.
pub(super) fn fingerprint(account: &DynamicAccount) -> String {
	match &account.rehashed {
		Some(kept) if kept.holds_for(account) => kept.fingerprint.clone(),
		_ => hash_digest(&marker(
			&account.password_hash,
			account.totp_secret.as_deref(),
		)),
	}
}

impl AccountStore {
	/// Rewrite the hash of `account` from `password`, which verified against
	/// `verified_hash`. Does nothing for an account that is not a dynamic
	/// one still holding that hash, so the work of hashing is not spent on
	/// a configured, SQL or LDAP account, or on a password that changed.
	pub(super) fn rehash_password(&self, account: &str, verified_hash: &str, password: &str) {
		let held = self
			.dynamic
			.read()
			.expect("store lock")
			.iter()
			.any(|row| row.name == account && row.password_hash == verified_hash);
		if !held {
			return;
		}
		// Hash outside the lock: the memory-hard function must not stall
		// every other reader of the store.
		let fresh = match crate::smtp::auth::upgraded_hash(verified_hash, password) {
			Some(Ok(fresh)) => fresh,
			Some(Err(error)) => return failed(account, &error),
			None => return,
		};
		let result = self.mutate_store(|state| {
			let row = state
				.accounts
				.iter_mut()
				.find(|row| row.name == account && row.password_hash == verified_hash)
				.ok_or_else(|| StoreError::Invalid("password rehash: no change".into()))?;
			let before = fingerprint(row);
			let origin = match &row.rehashed {
				Some(kept) if kept.holds_for(row) => kept.origin.clone(),
				_ => hash_digest(&row.password_hash),
			};
			row.password_hash = fresh;
			row.rehashed = Some(Rehashed {
				hash: hash_digest(&row.password_hash),
				second_factor: hash_digest(row.totp_secret.as_deref().unwrap_or("")),
				fingerprint: before,
				origin,
			});
			Ok(())
		});
		match result {
			Ok(()) => {
				tracing::info!(
					target: "epistle::auth",
					event = "password.rehash",
					account = %crate::log_id::account(account),
					"rewrote a password hash at the configured argon2id cost"
				);
			}
			// A concurrent sign-in or a password change got there first, or the
			// account is gone: nothing to write, nothing to say.
			Err(StoreError::Invalid(_)) => {}
			Err(error) => failed(account, &error.to_string()),
		}
	}
}

fn failed(account: &str, error: &str) {
	tracing::warn!(
		target: "epistle::auth",
		event = "password.rehash.failed",
		account = %crate::log_id::account(account),
		error = %error,
		"could not rewrite a password hash at the configured argon2id cost; the sign-in is not affected"
	);
}
