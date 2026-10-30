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
mod tests;
