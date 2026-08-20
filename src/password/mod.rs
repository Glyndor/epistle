//! Global password policy — enforced identically on every path that sets or
//! changes an account password (the management API and the CLI).
//!
//! Per the org security standard: length 12–64, **printable ASCII only** (no
//! control characters, no Unicode), **no composition rules** (ASVS v4 §2.1.9 and
//! NIST 800-63B advise against them), and rejection of **known-breached / common
//! passwords** via a bundled local list — the check that actually protects. The
//! list is local so validation works offline, with nothing phoning home.

use std::collections::HashSet;
use std::sync::OnceLock;

/// Minimum password length, in characters.
pub const MIN_LENGTH: usize = 12;

/// Maximum password length, in characters. A DoS ceiling on the Argon2 input,
/// generous enough that no real passphrase or password-manager output is
/// rejected; since the character set is printable ASCII, characters are bytes.
pub const MAX_LENGTH: usize = 64;

/// Why a candidate password was rejected by the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
	/// Fewer than [`MIN_LENGTH`] characters.
	TooShort,
	/// More than [`MAX_LENGTH`] characters.
	TooLong,
	/// Contains a character outside printable ASCII (a control character or any
	/// non-ASCII / Unicode byte).
	IllegalCharacter,
	/// Matches an entry in the bundled known-breached / common-password list.
	Breached,
}

impl Rejection {
	/// A user-facing, non-revealing explanation of the rejection, safe to return
	/// over the API or print at the CLI.
	pub fn message(self) -> &'static str {
		match self {
			Rejection::TooShort | Rejection::TooLong => {
				"Password must be between 12 and 64 characters."
			}
			Rejection::IllegalCharacter => {
				"Password may only contain printable ASCII characters (letters, digits, space and standard punctuation)."
			}
			Rejection::Breached => {
				"Password appears in a known breach or common-password list; choose a different one."
			}
		}
	}
}

/// The bundled breached / common-password list, one entry per line (`#` comments
/// and blank lines ignored). Every entry is at least [`MIN_LENGTH`] printable
/// ASCII characters, because anything shorter or non-ASCII is already rejected
/// before the breach lookup runs. This is a curated starter set; it is meant to
/// grow as larger vetted corpora (e.g. a HaveIBeenPwned ≥12-character export)
/// are folded in.
static BREACHED_RAW: &str = include_str!("breached_common.txt");

/// Build the breached-password set once, on first use.
fn breached_set() -> &'static HashSet<&'static str> {
	static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
	SET.get_or_init(|| {
		BREACHED_RAW
			.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty() && !line.starts_with('#'))
			.collect()
	})
}

/// Validate a candidate password against the global policy.
///
/// Returns `Ok(())` when the password is acceptable, or the first [`Rejection`]
/// that applies. Length and character set are checked before the breach lookup,
/// so a rejected password never reaches the (larger) breached-set membership
/// test unless it is a well-formed, in-range ASCII string.
pub fn validate(password: &str) -> Result<(), Rejection> {
	let length = password.chars().count();
	if length < MIN_LENGTH {
		return Err(Rejection::TooShort);
	}
	if length > MAX_LENGTH {
		return Err(Rejection::TooLong);
	}
	// Printable ASCII only: 0x20 (space) through 0x7E (`~`). This rejects control
	// characters and every non-ASCII (multibyte UTF-8) byte in one pass.
	if !password.bytes().all(|byte| (0x20..=0x7E).contains(&byte)) {
		return Err(Rejection::IllegalCharacter);
	}
	if breached_set().contains(password) {
		return Err(Rejection::Breached);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn accepts_a_strong_in_range_ascii_password() {
		// 16 chars, printable ASCII incl. space and punctuation, not breached.
		assert_eq!(validate("tR9 wq!zP4-mK7vX"), Ok(()));
	}

	#[test]
	fn accepts_the_length_boundaries() {
		let min = "aB3$".repeat(3); // exactly 12 characters
		assert_eq!(min.chars().count(), MIN_LENGTH);
		assert_eq!(validate(&min), Ok(()));
		let max = "aB3$".repeat(16); // exactly 64 characters
		assert_eq!(max.chars().count(), MAX_LENGTH);
		assert_eq!(validate(&max), Ok(()));
	}

	#[test]
	fn rejects_too_short() {
		assert_eq!(validate("aB3$aB3$aB3"), Err(Rejection::TooShort)); // 11
		assert_eq!(validate(""), Err(Rejection::TooShort));
	}

	#[test]
	fn rejects_too_long() {
		let long = "a".repeat(MAX_LENGTH + 1);
		assert_eq!(validate(&long), Err(Rejection::TooLong));
	}

	#[test]
	fn rejects_non_ascii_unicode() {
		// "contraseña" padded to length: the ñ makes it non-ASCII.
		assert_eq!(validate("contraseña99"), Err(Rejection::IllegalCharacter));
		assert_eq!(validate("straße straße"), Err(Rejection::IllegalCharacter));
		// Emoji is well past 12 chars and non-ASCII.
		assert_eq!(
			validate("🔒🔒🔒🔒🔒🔒🔒🔒🔒🔒🔒🔒"),
			Err(Rejection::IllegalCharacter)
		);
	}

	#[test]
	fn rejects_control_characters() {
		assert_eq!(validate("abcdef\tghijkl"), Err(Rejection::IllegalCharacter));
		assert_eq!(validate("abcdef\nghijkl"), Err(Rejection::IllegalCharacter));
		assert_eq!(validate("abcdef\0ghijkl"), Err(Rejection::IllegalCharacter));
	}

	#[test]
	fn rejects_a_breached_entry() {
		// Sample entries that must be present in the bundled list.
		assert_eq!(validate("password1234"), Err(Rejection::Breached));
		assert_eq!(validate("123456789012"), Err(Rejection::Breached));
		assert_eq!(validate("qwertyuiop12"), Err(Rejection::Breached));
	}

	#[test]
	fn every_bundled_entry_would_survive_the_earlier_checks() {
		// The breach list is only meaningful for entries that pass length and
		// character-set — otherwise they can never reach the lookup.
		for entry in breached_set() {
			let length = entry.chars().count();
			assert!(
				(MIN_LENGTH..=MAX_LENGTH).contains(&length),
				"breached entry {entry:?} is out of the length window"
			);
			assert!(
				entry.bytes().all(|b| (0x20..=0x7E).contains(&b)),
				"breached entry {entry:?} is not printable ASCII"
			);
		}
	}
}
