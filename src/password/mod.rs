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
	use crate::test_fixtures as fixtures;

	#[test]
	fn accepts_a_strong_in_range_ascii_password() {
		// Runtime credentials must pass the same policy as real account passwords.
		assert_eq!(validate(fixtures::password()), Ok(()));
	}

	#[test]
	fn accepts_the_length_boundaries() {
		let min = fixtures::printable_ascii(MIN_LENGTH);
		assert_eq!(min.chars().count(), MIN_LENGTH);
		assert_eq!(validate(&min), Ok(()));
		let max = fixtures::printable_ascii(MAX_LENGTH);
		assert_eq!(max.chars().count(), MAX_LENGTH);
		assert_eq!(validate(&max), Ok(()));
	}

	#[test]
	fn rejects_one_character_below_the_minimum() {
		let short = fixtures::printable_ascii(MIN_LENGTH - 1);
		assert_eq!(short.chars().count(), 11);
		assert_eq!(validate(&short), Err(Rejection::TooShort));
		assert_eq!(validate(&String::new()), Err(Rejection::TooShort));
	}

	#[test]
	fn rejects_one_character_above_the_maximum() {
		let long = fixtures::printable_ascii(MAX_LENGTH + 1);
		assert_eq!(long.chars().count(), 65);
		assert_eq!(validate(&long), Err(Rejection::TooLong));
	}

	#[test]
	fn rejects_a_non_ascii_character_anywhere_in_range() {
		for len in [MIN_LENGTH, MIN_LENGTH + 1, MAX_LENGTH - 1, MAX_LENGTH] {
			let text = fixtures::printable_ascii_with(fixtures::non_ascii_char(), len);
			assert_eq!(text.chars().count(), len, "length precondition");
			assert!(!text.is_ascii(), "shape precondition");
			assert_eq!(
				validate(&text),
				Err(Rejection::IllegalCharacter),
				"len {len}"
			);
		}
	}

	#[test]
	fn rejects_a_string_made_only_of_non_ascii_characters() {
		let text: String = (0..MIN_LENGTH)
			.map(|_| fixtures::non_ascii_char())
			.collect();
		assert_eq!(text.chars().count(), MIN_LENGTH);
		assert!(text.chars().all(|c| !c.is_ascii()), "shape precondition");
		assert_eq!(validate(&text), Err(Rejection::IllegalCharacter));
	}

	#[test]
	fn length_is_counted_in_characters_not_bytes() {
		// MAX_LENGTH multibyte characters are far more than MAX_LENGTH bytes,
		// yet the length check passes and the character set is what rejects.
		let text: String = (0..MAX_LENGTH)
			.map(|_| fixtures::non_ascii_char())
			.collect();
		assert_eq!(text.chars().count(), MAX_LENGTH);
		assert!(text.len() > MAX_LENGTH, "shape precondition");
		assert_eq!(validate(&text), Err(Rejection::IllegalCharacter));
	}

	#[test]
	fn rejects_every_control_character_anywhere_in_range() {
		let controls = fixtures::control_chars();
		assert_eq!(controls.len(), 33, "C0 controls plus DEL");
		for control in controls {
			let text = fixtures::printable_ascii_with(control, MIN_LENGTH + 1);
			assert_eq!(text.chars().count(), MIN_LENGTH + 1, "length precondition");
			assert_eq!(
				validate(&text),
				Err(Rejection::IllegalCharacter),
				"control U+{:04X}",
				u32::from(control)
			);
		}
	}

	#[test]
	fn rejects_every_bundled_breached_entry() {
		assert!(!breached_set().is_empty(), "the bundled list is not empty");
		for entry in breached_set() {
			assert_eq!(
				validate(entry),
				Err(Rejection::Breached),
				"bundled entry of {} characters",
				entry.chars().count()
			);
		}
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
