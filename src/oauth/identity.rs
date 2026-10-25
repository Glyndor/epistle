//! Which identity a validated token is allowed to name.
//!
//! A signature proves the identity provider issued the token, not that the
//! `email` inside it belongs to the person who asked for it: some providers
//! let a user edit that address or register one without confirming it. The
//! address is therefore taken only when the provider says it checked it
//! (`email_verified`), unless the operator declared that this provider does
//! not emit the claim. The `sub` claim is never an identity: it is an opaque
//! provider-local identifier and not a mailbox name.

use crate::jwt::Claims;

/// What the operator declared about the identity provider.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct IdentityPolicy {
	/// Accept an `email` claim that has no `email_verified`. A claim that
	/// says `false` is still refused.
	pub(super) allow_unverified_email: bool,
	/// The provider enforces a second factor of its own before it issues a
	/// token, so a bearer token may stand for an account that has a TOTP
	/// secret here.
	pub(super) second_factor_attested: bool,
}

impl IdentityPolicy {
	/// The `email` of `claims` when this policy lets it be an identity.
	pub(super) fn identity(&self, claims: &Claims) -> Option<String> {
		let email = claims.string("email")?;
		let admitted = match claims.raw.get("email_verified") {
			Some(serde_json::Value::Bool(verified)) => *verified,
			Some(serde_json::Value::String(text)) => text.eq_ignore_ascii_case("true"),
			Some(_) => false,
			None => self.allow_unverified_email,
		};
		admitted.then(|| email.to_string())
	}
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
