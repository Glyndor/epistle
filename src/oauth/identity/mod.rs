//! Which identity a validated token is allowed to name.
//!
//! A signature proves the identity provider issued the token, not that the
//! `email` inside it belongs to the person who asked for it: some providers
//! let a user edit that address or register one without confirming it. The
//! address is therefore taken only when the provider says it checked it
//! (`email_verified`), unless the operator declared that this provider does
//! not emit the claim. For a token of an external provider the `sub` claim is
//! never an identity: it is an opaque provider-local identifier and not a
//! mailbox name.
//!
//! The authorization server built into epistle is the exception. It signs
//! with a key of its own, names the account in `sub` and has already asked
//! for the second factor when it issued the token, so a verifier configured
//! with that key reads `sub` as the account and counts the factor as met.

use crate::jwt::Claims;

/// What the operator declared about the identity provider, and whether the
/// tokens are the ones epistle's own authorization server issues.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct IdentityPolicy {
	/// Accept an `email` claim that has no `email_verified`. A claim that
	/// says `false` is still refused.
	pub(super) allow_unverified_email: bool,
	/// The provider enforces a second factor of its own before it issues a
	/// token, so a bearer token may stand for an account that has a TOTP
	/// secret here.
	pub(super) second_factor_attested: bool,
	/// The tokens come from epistle's own authorization server.
	pub(super) own_tokens: bool,
}

/// Who a token says its bearer is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
	/// A mailbox address the provider vouched for.
	Address(String),
	/// An account name that epistle's own authorization server issued the
	/// token for.
	Account(String),
}

impl Verified {
	/// The text of the identity, whichever kind it is.
	pub fn as_str(&self) -> &str {
		match self {
			Verified::Address(text) | Verified::Account(text) => text,
		}
	}

	/// The local account this identity names, by an exact lookup: an address
	/// only through the address of an account, and never through a
	/// catch-all, a masked address or a sub-address.
	pub fn account(&self, directory: &crate::smtp::directory::Directory) -> Option<String> {
		match self {
			Verified::Address(text) => {
				let address = crate::smtp::address::Address::parse(text).ok()?;
				directory.resolve_exact(&address)
			}
			Verified::Account(name) => directory.named_account(name),
		}
	}
}

/// Why a token that passed its signature check names no identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
	/// A token of an external provider with no `email` claim.
	NoEmail,
	/// The `email_verified` claim is missing and the operator did not allow that.
	EmailVerifiedMissing,
	/// The provider says the address is not verified.
	EmailNotVerified,
	/// A token of the built-in server with no `sub`.
	NoSubject,
}

impl Refusal {
	/// The reason as the log states it, with no value from the token.
	pub(super) fn reason(self) -> &'static str {
		match self {
			Refusal::NoEmail => "the token has no email claim",
			Refusal::EmailVerifiedMissing => {
				"the token has no email_verified claim (see allow_unverified_email in [oauth])"
			}
			Refusal::EmailNotVerified => "the provider says the email is not verified",
			Refusal::NoSubject => "the token has no sub claim",
		}
	}
}

impl IdentityPolicy {
	/// The identity of `claims` under this policy.
	pub(super) fn identity(&self, claims: &Claims) -> Result<Verified, Refusal> {
		if self.own_tokens {
			return claims
				.string("sub")
				.map(|name| Verified::Account(name.to_string()))
				.ok_or(Refusal::NoSubject);
		}
		let email = claims.string("email").ok_or(Refusal::NoEmail)?;
		match claims.raw.get("email_verified") {
			Some(serde_json::Value::Bool(true)) => {}
			Some(serde_json::Value::String(text)) if text.eq_ignore_ascii_case("true") => {}
			Some(_) => return Err(Refusal::EmailNotVerified),
			None if self.allow_unverified_email => {}
			None => return Err(Refusal::EmailVerifiedMissing),
		}
		Ok(Verified::Address(email.to_string()))
	}

	/// Whether a token of this verifier already stands for the second factor.
	pub(super) fn second_factor_met(&self) -> bool {
		self.second_factor_attested || self.own_tokens
	}
}

#[cfg(test)]
mod tests;
