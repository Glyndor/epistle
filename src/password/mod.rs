//! Global password policy — enforced identically on every path that sets or
//! changes an account password (the management API and the CLI).
//!
//! Per the org security standard: length 12–64, **printable ASCII only** by
//! default (no control characters, no Unicode), **no composition rules** (ASVS
//! v4 §2.1.9 and NIST 800-63B advise against them), and rejection of
//! **known-breached / common passwords** via a bundled local list — the
//! check that actually protects. The list is local so validation works
//! offline, with nothing phoning home.
//!
//! The default ASCII-only character set keeps a strong guarantee that older
//! IMAP/POP clients receive and verify the same bytes that were set, since
//! AUTH PLAIN/LOGIN still ship the password on the wire as bytes. Operators
//! that need non-ASCII passwords flip `[auth] unicode_passwords = true`. With
//! it on the policy accepts any non-control Unicode scalar, normalises with
//! NFKC on both set and verify (so a password set with one keyboard verifies
//! from another, RFC 8265 OpaqueString profile), counts length in scalars,
//! and keeps the 64-character ceiling on the normalised form. The runtime
//! shape of the new behaviour lives in [`Policy`] under [`policy`].

use std::collections::HashSet;
use std::sync::OnceLock;

pub mod policy;

pub use policy::Policy;

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
	/// non-ASCII / Unicode byte), or a Unicode control scalar when
	/// `[auth] unicode_passwords` is on.
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

/// The bundled NCSC top-100k list, already filtered to the entries the
/// policy can consult (12 to 64 printable-ASCII characters). Source, checksum
/// of the unfiltered file and both licence credits are in the file's header
/// and in `debian/copyright`.
pub(super) static BREACHED_RAW_TOP100K: &str = include_str!("breached_top100k.txt");

/// Whether a raw password entry (one trimmed line of one of the bundled
/// files) survives the early checks the policy applies before the breach
/// lookup. The lookup key is the case-folded form, so the check runs on the
/// lowered entry and rejects every entry that the validate pass would have
/// rejected for the same reason.
fn survives_filter(entry: &str) -> bool {
	let lowered = entry.to_ascii_lowercase();
	let length = lowered.chars().count();
	if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
		return false;
	}
	lowered.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
}

/// Build the breached-password set once, on first use. Combines the legacy
/// curated list and the bundled top-100k so that any entry that survives the
/// length and printable-ASCII gate, in either file, is refused as a breach.
/// The set keys are case-folded so the lookup is case-insensitive regardless
/// of which source row carried that entry.
pub(super) fn breached_set() -> &'static HashSet<&'static str> {
	static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
	SET.get_or_init(|| {
		let mut set: HashSet<&'static str> = HashSet::with_capacity(2048);
		for raw in [BREACHED_RAW, BREACHED_RAW_TOP100K] {
			for line in raw.lines() {
				let trimmed = line.trim();
				if trimmed.is_empty() || trimmed.starts_with('#') || !survives_filter(trimmed) {
					continue;
				}
				// Leaked once at first use: a few kilobytes for the life of
				// the process, in exchange for `&'static str` keys.
				set.insert(Box::leak(trimmed.to_ascii_lowercase().into_boxed_str()));
			}
		}
		set
	})
}

/// Validate a candidate password against the historical ASCII-only policy.
///
/// This is the entry point every existing call site uses; it preserves the
/// pre-unicode behaviour exactly (printable ASCII only, no normalisation,
/// case-insensitive breach lookup against the bundled set). New code that
/// needs Unicode support should construct a [`Policy::unicode`] and call
/// its `validate`.
pub fn validate(password: &str) -> Result<(), Rejection> {
	Policy::ASCII_ONLY.validate(password)
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
		let empty = fixtures::printable_ascii(0);
		assert!(empty.is_empty(), "shape precondition");
		assert_eq!(validate(&empty), Err(Rejection::TooShort));
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

	/// Entries of the bundled top-100k file, without its comment header.
	fn top100k_entries() -> impl Iterator<Item = &'static str> {
		super::BREACHED_RAW_TOP100K
			.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty() && !line.starts_with('#'))
	}

	#[test]
	fn the_top100k_file_ships_only_entries_the_lookup_can_reach() {
		// The file is filtered when it is imported. An unfiltered paste would
		// add close to a megabyte of entries that can never be looked up.
		let mut count = 0;
		for entry in top100k_entries() {
			count += 1;
			assert!(
				survives_filter(entry),
				"entry {entry:?} can never reach the lookup"
			);
		}
		assert!(count > 1000, "only {count} entries in the top-100k file");
	}

	#[test]
	fn every_top100k_entry_is_refused_as_breached() {
		for entry in top100k_entries() {
			assert_eq!(validate(entry), Err(Rejection::Breached), "{entry:?}");
		}
	}

	#[test]
	fn a_known_entry_lookup_is_case_insensitive() {
		// Digits have no case, so pick an entry with a letter in it.
		let entry = top100k_entries()
			.find(|entry| entry.bytes().any(|b| b.is_ascii_lowercase()))
			.expect("the list has an entry with a lowercase letter");
		let upper = entry.to_ascii_uppercase();
		assert_ne!(upper, entry, "shape precondition: uppercasing changed it");
		assert_eq!(validate(&upper), Err(Rejection::Breached), "{upper:?}");
	}

	#[test]
	fn a_fresh_random_password_still_passes_with_the_real_list() {
		// The bundled 100k list is bigger by a wide margin; this exercises a
		// strong random credential (URL-safe base64, all printable ASCII) so
		// the breach check is run against the bundled set on a value that
		// cannot be in it.
		let password = fixtures::printable_ascii(MIN_LENGTH + 8);
		assert!(
			!breached_set().contains(password.as_str()),
			"shape precondition: a freshly-generated password must not be in the bundle"
		);
		assert_eq!(validate(&password), Ok(()));
	}

	#[test]
	fn the_bundled_lookup_set_covers_more_than_five_hundred_entries() {
		// Anything under a few hundred would mean the bundle has stopped
		// being effective.
		assert!(
			breached_set().len() > 500,
			"bundled lookup set is {} entries, expected a substantial list",
			breached_set().len(),
		);
	}
}

#[cfg(test)]
#[path = "tests_unicode.rs"]
mod tests_unicode;
