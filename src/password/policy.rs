//! Runtime password policy.
//!
//! Separated from `mod.rs` so the storage layer can carry a `Policy` by
//! value without dragging the ASCII-only `validate` and the breached-list
//! build into every call site. The same `Policy` is used by:
//!
//! - every validator (CLI, the management API, SCIM, `init`), through
//!   [`Policy::validate`],
//! - the storage layer, which calls [`Policy::prepare`] on the candidate
//!   before hashing it with argon2id or feeding it to SCRAM, so the set
//!   and verify forms are computed on identical bytes.

use std::borrow::Cow;

use unicode_normalization::UnicodeNormalization;

use super::{MAX_LENGTH, MIN_LENGTH, Rejection, breached_set};

/// The runtime password policy. Both the validation gate (used by every
/// caller that sets or rotates an account password) and the byte-for-byte
/// preparation the storage layer applies to a candidate before hashing go
/// through this struct, so set-time and verify-time agree on what the
/// stored hash and SCRAM verifier actually represent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
	/// When `true`, accept any non-control Unicode scalar, normalise with
	/// NFKC for hashing, and count length in scalars (still 12-64 on the
	/// normalised form). When `false` (the historical default), only
	/// printable ASCII is accepted and no normalisation runs.
	pub unicode_passwords: bool,
}

impl Policy {
	/// A policy that requires printable ASCII only — the historical
	/// default and the behaviour that older IMAP/POP clients expect from
	/// AUTH PLAIN/LOGIN without surprises.
	pub const ASCII_ONLY: Self = Self {
		unicode_passwords: false,
	};

	/// A policy that accepts NFKC-normalised Unicode passwords. Both set
	/// and verify normalise the candidate so a password set with one
	/// keyboard verifies from another.
	pub fn unicode() -> Self {
		Self {
			unicode_passwords: true,
		}
	}

	/// Normalise `password` for storage or verification. With
	/// `unicode_passwords = false` this enforces the historical ASCII-only
	/// gate (printable ASCII, length 12-64): the input is borrowed as-is
	/// when it survives, and rejected as `IllegalCharacter`, `TooShort`, or
	/// `TooLong` when it does not. With the flag on the caller submits
	/// whatever form the client supplied; the password comes back in NFKC,
	/// so the argon2id hash and the SCRAM `SaltedPassword` are both derived
	/// from the canonical form, and a password set with one keyboard
	/// verifies from another.
	///
	/// Returns the same `Err` as `validate` because the input can still be
	/// too short, too long, or carry a forbidden scalar (control); set-time
	/// callers usually run `validate` first and pass its result through here
	/// anyway.
	pub fn prepare<'a>(&self, password: &'a str) -> Result<Cow<'a, str>, Rejection> {
		if !self.unicode_passwords {
			let length = password.chars().count();
			if length < MIN_LENGTH {
				return Err(Rejection::TooShort);
			}
			if length > MAX_LENGTH {
				return Err(Rejection::TooLong);
			}
			// Printable ASCII only: 0x20 (space) through 0x7E (`~`). This
			// rejects control characters and every non-ASCII (multibyte
			// UTF-8) byte in one pass, matching the pre-unicode behaviour.
			if !password.bytes().all(|byte| (0x20..=0x7E).contains(&byte)) {
				return Err(Rejection::IllegalCharacter);
			}
			return Ok(Cow::Borrowed(password));
		}
		// NFKC first so the length and control checks see the canonical form.
		let normalised: String = password.nfkc().collect();
		let length = normalised.chars().count();
		if length < MIN_LENGTH {
			return Err(Rejection::TooShort);
		}
		if length > MAX_LENGTH {
			return Err(Rejection::TooLong);
		}
		if let Some(control) = normalised.chars().find(|c| is_control(*c)) {
			// Avoid printing the scalar itself; reveal only the code point.
			return Err(control_rejection(control));
		}
		Ok(Cow::Owned(normalised))
	}

	/// Validate a candidate password against this policy. Both the
	/// ASCII-only and the Unicode paths share the bundle-lookup, so a strong
	/// random candidate passes both and a known breach is refused by both.
	pub fn validate(&self, password: &str) -> Result<(), Rejection> {
		let prepared = self.prepare(password)?;
		check_bundled_breach(&prepared)
	}

	/// Build from the operator's `[auth]` configuration. Absent defaults to
	/// the historical ASCII-only behaviour so a config that never mentions
	/// the new flag stays unchanged.
	pub fn from_config(auth: &crate::config::Auth) -> Self {
		Self {
			unicode_passwords: auth.unicode_passwords,
		}
	}
}

/// Case-insensitive breach lookup used by every `Policy` after the candidate
/// has cleared length and character-set. The bundled set is keyed by the
/// lower-case form, so a candidate that only differs in capitalisation from
/// a known breach still hits the row.
fn check_bundled_breach(prepared: &str) -> Result<(), Rejection> {
	let lowered = prepared.to_ascii_lowercase();
	if breached_set().contains(lowered.as_str()) {
		return Err(Rejection::Breached);
	}
	Ok(())
}

/// Returns the right rejection enum for a forbidden control scalar without
/// leaking it on the wire or in a log line.
fn control_rejection(control: char) -> Rejection {
	debug_assert!(is_control(control));
	Rejection::IllegalCharacter
}

/// `true` for `U+0000..=U+001F`, `U+007F..=U+009F` (the C0/C1 control
/// ranges), and the bidi / line-separator / paragraph-separator characters
/// SASLprep (RFC 4013) rejects and RFC 8265 OpaqueString keeps out of the
/// canonical form.
fn is_control(c: char) -> bool {
	matches!(c,
		'\u{0000}'..='\u{001F}'
		| '\u{007F}'..='\u{009F}'
		| '\u{202A}'..='\u{202E}'
		| '\u{2066}'..='\u{2069}'
		| '\u{200B}'..='\u{200F}'
		| '\u{2028}' | '\u{2029}'
	)
}
