//! IMAP user-defined keywords (RFC 9051 section 2.3.2).
//!
//! A keyword is an atom the server stores alongside its system flags and
//! renders back to clients without case folding (case is preserved in the
//! sidecar and on the wire). The reserved set (`$Junk`, `$NotJunk`,
//! `$Forwarded`, `$Phishing`, `$Important`) is enforced as constants in
//! this module so the cross-feature code (the Bayesian trainer, the
//! JMAP Email/set path) can refer to them by name without spelling the
//! wire token inline at every site.
//!
//! Validation follows RFC 9051 §2.3.2: an atom without `\`, spaces,
//! `(`, `)`, `{`, `%`, `*`, `"`, `]`, or a control byte, and at most
//! 64 bytes long. A message carries at most 32 keywords (STORE and
//! APPEND refuse more with `BAD`).

use serde::{Deserialize, Serialize};

/// Reserved keywords from RFC 5788 / RFC 9051 §2.3.2. Used by code paths
/// that observe transitions (the Bayesian trainer) or that need a
/// case-insensitive set for rendering (SELECT, JMAP round-trip). Clients
/// are free to use any other atom too. These constants exist for the
/// server's own bookkeeping.
pub const JUNK: &str = "$Junk";
/// Reserved keyword: `$NotJunk` (the "this is not spam" marker).
pub const NOT_JUNK: &str = "$NotJunk";
/// Reserved keyword: `$Forwarded`.
pub const FORWARDED: &str = "$Forwarded";
/// Reserved keyword: `$Phishing`.
pub const PHISHING: &str = "$Phishing";
/// Reserved keyword: `$Important`.
pub const IMPORTANT: &str = "$Important";

/// Maximum number of distinct keywords a single message may carry.
/// Exceeding it makes STORE and APPEND answer `BAD` so the wire stays
/// well-formed and the sidecar never overflows an arbitrary cap.
pub const MAX_KEYWORDS_PER_MESSAGE: usize = 32;

/// Maximum length, in bytes, of one keyword atom.
pub const MAX_KEYWORD_BYTES: usize = 64;

/// Validate an IMAP user-defined keyword atom.
///
/// Returns `Ok(())` for any keyword the wire format would carry: 1..=64
/// bytes of plain ASCII (the IMAP atom production in RFC 9051
/// section 2.3.2), no characters from the `atom-specials` set
/// (`(`, `)`, `{`, ` `, `%`, `*`, `"`, `]`, `\`), no leading `\` (the
/// backslash prefix is reserved for system flags), no control bytes,
/// and no byte with the high bit set. Empty input is rejected:
/// `Flag::parse` already treats `""` as `None`. The leading character
/// is the one the standard reserves for system flags; clients that
/// try `\Custom` go through `Flag::parse`, which would map it to
/// `None`.
pub fn validate(token: &str) -> Result<(), &'static str> {
	if token.is_empty() {
		return Err("empty keyword");
	}
	if token.len() > MAX_KEYWORD_BYTES {
		return Err("keyword too long");
	}
	if token.starts_with('\\') {
		return Err("keyword starts with backslash");
	}
	for byte in token.bytes() {
		// 0x7F (DEL) is the only ASCII control byte `is_ascii_control`
		// catches that is also a non-ASCII char; reject it explicitly
		// so the rule reads "no control byte" without surprises.
		if byte.is_ascii_control() {
			return Err("keyword contains a control byte");
		}
		if byte >= 0x80 {
			return Err("keyword contains a non-ASCII byte");
		}
		match byte {
			b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b']' | b'\\' => {
				return Err("keyword contains an atom-special");
			}
			_ => {}
		}
	}
	Ok(())
}

/// Whether two keywords are the same, case-insensitively.
///
/// IMAP keyword matching is case-insensitive: RFC 3501 §2.3.2 and the
/// IMAP4rev2 base say atoms are matched without regard to case. The
/// sidecar and the wire preserve case so the user sees what they set;
/// equality here is the matching rule the store applies when SEARCH
/// asks for a particular keyword.
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
	a.eq_ignore_ascii_case(b)
}

/// A keyword's serde shape: the raw token with its leading `$` (or any
/// other reserved prefix) preserved. Keeps the system flags' wire form
/// (no JSON-string wrapper) so the file format stays compatible with
/// sidecars written before keywords existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keyword(
	/// The keyword as the user typed it (case preserved).
	#[serde(deserialize_with = "deserialize_validated")]
	String,
);

/// Validate on deserialize so a corrupt sidecar cannot smuggle a bad
/// token through. The `transparent` wrapper hands the inner string here.
fn deserialize_validated<'de, D>(deserializer: D) -> Result<String, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let raw = String::deserialize(deserializer)?;
	validate(&raw)
		.map_err(|reason| serde::de::Error::custom(format!("invalid keyword {raw:?}: {reason}")))?;
	Ok(raw)
}

impl Keyword {
	/// Build a keyword from a wire token, validating the atom.
	pub fn new(token: &str) -> Result<Self, &'static str> {
		validate(token)?;
		Ok(Keyword(token.to_string()))
	}

	/// Borrow the keyword's raw token (case preserved, no `$` stripped).
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// Whether the keyword matches `needle` case-insensitively.
	pub fn matches(&self, needle: &str) -> bool {
		eq_ignore_case(&self.0, needle)
	}

	/// True when the keyword is the reserved `$Junk` marker.
	pub fn is_junk(&self) -> bool {
		eq_ignore_case(&self.0, JUNK)
	}

	/// True when the keyword is the reserved `$NotJunk` marker.
	pub fn is_not_junk(&self) -> bool {
		eq_ignore_case(&self.0, NOT_JUNK)
	}
}

impl std::fmt::Display for Keyword {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

#[cfg(test)]
#[path = "keyword_tests.rs"]
mod tests;
