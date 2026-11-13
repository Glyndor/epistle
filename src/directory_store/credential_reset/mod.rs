//! The reset of an account's credentials after a compromise.
//!
//! `epistle rotate` resets the dynamic accounts whose password hashes may
//! have been taken with `accounts.toml`: each one gets the hash of a secret
//! nobody holds, loses its SCRAM verifier and its TOTP secret, and records in
//! [`CredentialReset`] what it still needs. While that record is there the
//! directory refuses every sign-in of the account
//! ([`crate::smtp::directory::Directory::admit_login`]) and a key bound to it
//! stops working ([`super::AccountStore::is_locked`]).
//!
//! Only an administrator lifts it. A new password clears
//! [`CredentialReset::password`]; a new TOTP enrolment, or the explicit
//! removal of the second factor, clears [`CredentialReset::second_factor`].
//! A full replacement of the record (SCIM `PUT`) keeps the stored
//! credentials and the reset unless it brings a new password on purpose, so
//! it cannot unlock an account with its old password.

use serde::{Deserialize, Serialize};

use super::{AccountStore, DynamicAccount, StoreError};

/// What a reset account still needs before it signs in again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReset {
	/// A new password, set by an administrator.
	#[serde(default)]
	pub password: bool,
	/// A new second factor: the account had a TOTP secret when it was reset.
	#[serde(default)]
	pub second_factor: bool,
}

impl CredentialReset {
	/// The record to keep, or `None` once nothing is left to do.
	fn left(self) -> Option<Self> {
		(self.password || self.second_factor).then_some(self)
	}
}

/// An account a reset was decided for, and the digest of the password hash
/// it held then. The reset touches it only while it still holds that hash,
/// so a password an administrator set in the meantime is never undone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetTarget {
	/// The dynamic account.
	pub name: String,
	/// [`hash_digest`] of its password hash.
	pub digest: String,
}

/// The sha256 of a stored password hash, in hex. A record of the reset keeps
/// this and never the hash, which could be attacked offline.
pub fn hash_digest(hash: &str) -> String {
	crate::api::api_keys::sha256_hash(hash)
}

/// A new password was stored for `account`.
pub(super) fn password_replaced(account: &mut DynamicAccount) {
	account.reset = account.reset.and_then(|reset| {
		CredentialReset {
			password: false,
			..reset
		}
		.left()
	});
}

/// A TOTP secret was enrolled for `account`, or its second factor removed.
pub(super) fn second_factor_replaced(account: &mut DynamicAccount) {
	account.reset = account.reset.and_then(|reset| {
		CredentialReset {
			second_factor: false,
			..reset
		}
		.left()
	});
}

/// A new password that comes with a full replacement of the record, as its
/// argon2id hash and SCRAM verifier.
#[derive(Debug, Clone)]
pub struct NewPassword {
	/// The argon2id PHC hash.
	pub hash: String,
	/// The SCRAM-SHA-256 verifier; `None` when SCRAM is off.
	pub scram: Option<crate::smtp::scram::ScramStored>,
}

/// Give `fresh`, the full replacement of `previous`, the credentials
/// `previous` holds now: its password, verifier, TOTP secret and reset. The
/// replacement may have been built from an older read, so what it says about
/// them is not used. Only `new_password`, which the caller passes on
/// purpose, changes the password and settles that part of a reset.
pub(super) fn carry(
	previous: &DynamicAccount,
	fresh: &mut DynamicAccount,
	new_password: Option<NewPassword>,
) {
	fresh.password_hash.clone_from(&previous.password_hash);
	fresh.scram.clone_from(&previous.scram);
	fresh.totp_secret.clone_from(&previous.totp_secret);
	fresh.reset = previous.reset;
	if let Some(NewPassword { hash, scram }) = new_password {
		fresh.password_hash = hash;
		fresh.scram = scram;
		password_replaced(fresh);
	}
}

/// The accounts that wait for a reset to be completed.
pub(super) fn names(dynamic: &[DynamicAccount]) -> Vec<String> {
	dynamic
		.iter()
		.filter(|account| account.reset.is_some())
		.map(|account| account.name.clone())
		.collect()
}

impl AccountStore {
	/// Reset the credentials of every target that still holds the password
	/// hash it had when the reset was decided, in one write. `placeholder` is
	/// the hash of a secret nobody holds: it takes the place of the password,
	/// so the old one stops verifying even before the directory reads the
	/// record. Returns the accounts reset; a target that is gone, or whose
	/// password changed since, is left alone.
	pub fn reset_credentials(
		&self,
		targets: &[ResetTarget],
		placeholder: &str,
	) -> Result<Vec<String>, StoreError> {
		let mut reset = Vec::new();
		self.mutate_store(|state| {
			for target in targets {
				let Some(account) = state
					.accounts
					.iter_mut()
					.find(|account| account.name == target.name)
				else {
					continue;
				};
				if hash_digest(&account.password_hash) != target.digest {
					continue;
				}
				account.reset = Some(CredentialReset {
					password: true,
					second_factor: account.totp_secret.is_some()
						|| account.reset.is_some_and(|reset| reset.second_factor),
				});
				account.password_hash = placeholder.to_string();
				account.scram = None;
				account.totp_secret = None;
				reset.push(account.name.clone());
			}
			Ok(())
		})?;
		Ok(reset)
	}

	/// Whether the dynamic account `name` may not act at all: it is disabled,
	/// or its credentials were reset and are not replaced yet.
	pub fn is_locked(&self, name: &str) -> bool {
		self.dynamic
			.read()
			.expect("store lock")
			.iter()
			.find(|account| account.name == name)
			.is_some_and(|account| account.disabled || account.reset.is_some())
	}
}

#[cfg(test)]
mod tests;
