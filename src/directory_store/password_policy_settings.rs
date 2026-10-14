//! Password policy wiring on [`super::AccountStore`].
//!
//! The `with_password_policy` / `password_policy` pair live in a sibling
//! file so [`super::AccountStore`] in `mod.rs` stays under the per-file
//! code-line budget. The store applies the policy at every path that
//! handles plaintext passwords (set/change, verify, app-password verify);
//! `set_password_hash` runs the SCRAM/argon2id derivations on whatever
//! bytes the policy produces, so the bytes hashed at set-time always match
//! the bytes verified at login-time.

use super::Policy;

impl super::AccountStore {
	/// Replace the runtime password policy. Wired from
	/// `[auth] unicode_passwords` at startup; the store defaults to
	/// `Policy::ASCII_ONLY` until this is called, so existing test wiring
	/// that never mentions the policy keeps the historical behaviour.
	pub fn with_password_policy(mut self, policy: Policy) -> Self {
		self.password_policy = policy;
		self
	}

	/// The runtime password policy. Used by the password-mutating paths so
	/// the bytes hashed and verified are computed identically on both
	/// sides.
	pub fn password_policy(&self) -> Policy {
		self.password_policy
	}
}
