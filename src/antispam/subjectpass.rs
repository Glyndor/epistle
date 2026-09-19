//! SubjectPass: a signed retry token for the uncertain Bayesian band.
//!
//! When a message's local Bayesian score lands in the configured uncertain
//! band and no LLM verdict decides it (no LLM configured, or the call
//! failed), the server faces a binary choice: accept or reject. Both have a
//! cost: a quiet accept teaches the classifier that "uncertain" is the
//! same as "spam" if it really is, and a hard reject bounces legitimate
//! mail. SubjectPass splits the difference: refuse with a token the sender
//! can put in the subject, and accept the resend that carries it.
//!
//! ## Why a permanent refusal, not a tempfail
//!
//! The challenge only works if a person reads it. A sending MTA that is
//! given a 4xx keeps the message queued and retries the same bytes, which
//! never carry the token, so every retry is challenged again and the author
//! hears nothing until that queue gives up days later. A 5xx makes the
//! sending MTA bounce at once, and the bounce quotes the reply text with the
//! token in it. A spam cannon opens one socket and never reads its bounce.
//!
//! The message is dropped when it is challenged: it is not stored, and it
//! does not train the corpus in either direction, because the server has
//! asked a question rather than reached a verdict.
//!
//! Greylisting keys on (client, sender, recipient) triplets; SubjectPass
//! keys on (sender, recipient, day) signed with a per-instance HMAC key, so
//! the resend does not need to come from the same IP, and a stolen token
//! gains exactly one sender/recipient pair for one day.
//!
//! ## The token
//!
//! ```text
//!   EP-<base32(HMAC-SHA256(key, lower(sender)|lower(recipient)|day))[:12]>
//! ```
//!
//! The 12-character prefix is 60 bits, plenty for replay resistance inside
//! the day window. The day is the same two-character base32 day stamp SRS
//! uses (a `days mod 1024` value), so a token minted today also verifies
//! yesterday's day stamp and vice versa; a sender who retries past
//! midnight still passes. The key lives outside the database (so a DB
//! compromise cannot forge tokens), the file is `0600`, and a fresh install
//! has the helper mint a new one.
//!
//! ## Where the check runs
//!
//! Before the band is consulted, on every unauthenticated message: if the
//! `Subject:` header contains a valid token for this sender, recipient and
//! day or yesterday, accept the message as ham (skip the band, train the
//! shared corpus as an accepted message would). An invalid token is ignored,
//! not an error. The check runs after DNSBL, SPF, DMARC and the scanner hook,
//! so a valid token never overrides a hard rejection.

use std::path::Path;

use ring::hmac;

use crate::storage::load_or_create_key_file;
use crate::util::constant_time;

/// The SubjectPass token prefix the sender pastes into the subject. The
/// short string makes the token visually distinct from the rest of the
/// subject and lets a parser find it without parsing the whole header value.
pub const TOKEN_PREFIX: &str = "EP-";

/// The base32 day-stamp alphabet, matching [`crate::queue::srs`]. Two
/// characters encode `days mod 1024`, so today and yesterday both verify.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TS_MODULUS: u64 = 1024;

/// Number of base32 characters of the HMAC that form the on-wire token.
/// 12 chars × 5 bits/char = 60 bits, plenty for replay resistance inside
/// the two-day window.
const TOKEN_CHARS: usize = 12;

/// Encode `days` (UNIX seconds / 86400) as the same two-character base32
/// stamp SRS uses.
fn encode_day(days: u64) -> String {
	let value = (days % TS_MODULUS) as usize;
	let hi = BASE32[(value >> 5) & 31] as char;
	let lo = BASE32[value & 31] as char;
	format!("{hi}{lo}")
}

/// Base32-encode a byte slice using the SRS alphabet, MSB-first.
fn base32_encode(bytes: &[u8]) -> String {
	let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
	let mut buffer: u64 = 0;
	let mut bits: u32 = 0;
	for byte in bytes {
		buffer = (buffer << 8) | u64::from(*byte);
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			let index = ((buffer >> bits) & 0x1f) as usize;
			out.push(BASE32[index] as char);
		}
	}
	if bits > 0 {
		let index = ((buffer << (5 - bits)) & 0x1f) as usize;
		out.push(BASE32[index] as char);
	}
	out
}

/// The signed-token store for SubjectPass.
pub struct SubjectPass {
	key: hmac::Key,
}

impl SubjectPass {
	/// Load the per-instance HMAC key from `data_dir`, generating and
	/// persisting a fresh `0600` key on first use. The key file is
	/// `subjectpass.key`; the corpus uses a different filename, so the two
	/// features can rotate their keys independently.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let key = load_or_create_key_file(data_dir, "subjectpass.key")?;
		Ok(Self::with_key(key))
	}

	/// Build a verifier from an explicit 32-byte key. Tests use this to
	/// avoid the filesystem.
	pub fn with_key(key: [u8; 32]) -> Self {
		SubjectPass {
			key: hmac::Key::new(hmac::HMAC_SHA256, &key),
		}
	}

	/// Mint a token for `sender` (envelope MAIL FROM) addressing
	/// `recipient` (the first RCPT TO of the message) on `day` (UNIX
	/// seconds / 86400). Returns `EP-<12 chars>`; `lowercase sender|lowercase
	/// recipient|day-stamp` is the HMAC payload.
	pub fn issue(&self, sender: &str, recipient: &str, day: u64) -> String {
		let payload = format!(
			"{}|{}|{}",
			sender.to_ascii_lowercase(),
			recipient.to_ascii_lowercase(),
			encode_day(day),
		);
		let tag = hmac::sign(&self.key, payload.as_bytes());
		let encoded = base32_encode(tag.as_ref());
		let token: String = encoded.chars().take(TOKEN_CHARS).collect();
		format!("{TOKEN_PREFIX}{token}")
	}

	/// Verify `candidate` (with or without the `EP-` prefix) for the given
	/// `sender`/`recipient` on `day`. The day stamp must match either
	/// `day` or `day - 1` (wrapping at the 1024-day boundary the same way
	/// SRS handles wrap-around), so a token minted before midnight and
	/// retried after still verifies.
	///
	/// The comparison is constant-time against both candidate stamps; a
	/// length mismatch short-circuits to `false` because the candidate
	/// length is already public.
	pub fn verify(&self, candidate: &str, sender: &str, recipient: &str, day: u64) -> bool {
		let token = candidate.strip_prefix(TOKEN_PREFIX).unwrap_or(candidate);
		if token.len() != TOKEN_CHARS {
			return false;
		}
		let token_bytes = token.as_bytes();
		let yesterday = day.wrapping_sub(1);
		// Compare against both stamps in constant time. Always evaluate both
		// candidates so the wall-clock does not depend on which day matches.
		let mut ok = false;
		for &d in &[day, yesterday] {
			let expected = self.issue(sender, recipient, d);
			let expected_token = expected.strip_prefix(TOKEN_PREFIX).unwrap();
			if constant_time::eq(token_bytes, expected_token.as_bytes()) {
				ok = true;
			}
		}
		ok
	}

	/// Whether the given `subject` header value contains a valid SubjectPass
	/// token for `sender`, `recipient`, and `day` (or yesterday). Returns
	/// `false` for an absent or malformed subject; an invalid token is
	/// silently ignored, not an error. The token search is case-insensitive
	/// (the prefix and the base32 suffix), so a sender who pastes the token
	/// in mixed case still passes. RFC 2047 encoded-words in the subject are
	/// decoded first: a sender whose mail client encoded an accent in the
	/// subject still gets the token check on the decoded text.
	pub fn accepts(&self, subject: Option<&str>, sender: &str, recipient: &str, day: u64) -> bool {
		let Some(subject) = subject else {
			return false;
		};
		// RFC 2047 decode first, so an accent in the original Subject: does
		// not push a token-prefixed word into the next encoded-word. A
		// malformed encoded-word is left as is by the decoder, so the
		// tokenizer below still finds a plain `EP-...` token.
		let decoded = crate::util::encoded_word::decode(subject);
		for word in decoded.split_whitespace() {
			// Match the prefix case-insensitively so a sender who types `ep-`
			// or who copies the token with mixed case still hits the check.
			let after_prefix = match strip_prefix_ci(word, TOKEN_PREFIX) {
				Some(rest) => rest,
				None => continue,
			};
			if after_prefix.len() != TOKEN_CHARS {
				continue;
			}
			if after_prefix
				.bytes()
				.any(|b| !is_base32_char(b.to_ascii_uppercase()))
			{
				continue;
			}
			// Normalise to uppercase for the verifier (the token is base32
			// uppercase; the verifier does the same on its computed value).
			let normalised = after_prefix.to_ascii_uppercase();
			if self.verify(&normalised, sender, recipient, day) {
				return true;
			}
		}
		false
	}
}

/// Whether `b` is one of the SRS base32 alphabet characters.
fn is_base32_char(b: u8) -> bool {
	b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)
}

/// Strip `prefix` from the start of `text` ignoring ASCII case.
fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
	if text.len() >= prefix.len()
		&& text.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
	{
		Some(&text[prefix.len()..])
	} else {
		None
	}
}

/// Locate the first RFC 5322 header named `name` (case-insensitive) and
/// return its unfolded value. `None` if absent or the header block is not
/// valid UTF-8. Mirrors the helper in [`crate::rules`] so the verification
/// path is independent of the rules module.
pub fn header_value(raw: &[u8], name: &str) -> Option<String> {
	let end = find_header_end(raw).unwrap_or(raw.len());
	let headers = std::str::from_utf8(&raw[..end]).ok()?;
	let prefix = format!("{name}:").to_ascii_lowercase();
	let mut lines = headers.split_inclusive("\r\n").peekable();
	while let Some(line) = lines.next() {
		if line.to_ascii_lowercase().starts_with(&prefix) {
			let mut value = line[prefix.len()..].trim().to_string();
			while let Some(cont) = lines.peek() {
				if cont.starts_with(' ') || cont.starts_with('\t') {
					value.push(' ');
					value.push_str(cont.trim());
					lines.next();
				} else {
					break;
				}
			}
			return Some(value);
		}
	}
	None
}

/// Index of the end of the header block (the empty line), if present.
fn find_header_end(raw: &[u8]) -> Option<usize> {
	raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 2)
}

/// The SMTP reply text a sender sees when SubjectPass challenges them. It
/// reaches a person inside the bounce their own MTA writes, so it is one
/// plain sentence plus the token to put in the subject. `<token>` stands for
/// the whole token, prefix included.
pub const CHALLENGE_TEXT: &str =
	"this message needs a human; resend it with <token> anywhere in the subject";

/// Compose the `550 5.7.1 ...` reply with a freshly minted token in place
/// of `<token>`. The code is permanent on purpose: see the module docs.
pub fn challenge_reply(
	pass: &SubjectPass,
	sender: &str,
	recipient: &str,
	day: u64,
) -> crate::smtp::reply::Reply {
	let token = pass.issue(sender, recipient, day);
	let body = CHALLENGE_TEXT.replace("<token>", &token);
	crate::smtp::reply::Reply::single(550, &format!("5.7.1 {body}"))
}

#[cfg(test)]
#[path = "subjectpass_tests.rs"]
mod tests;
