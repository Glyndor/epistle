//! Time-based one-time passwords (TOTP, RFC 6238) for two-factor auth.
//!
//! The shared secret is HMAC'd with a time counter to derive a short numeric
//! code; verification accepts a small window of adjacent steps for clock skew.
//! HMAC-SHA1 is the de-facto standard authenticator-app algorithm.

use ring::hmac;

use crate::util::constant_time;

/// The HOTP/TOTP step in seconds (RFC 6238 default).
pub const STEP_SECONDS: u64 = 30;
/// Number of code digits (RFC 6238 default).
pub const DIGITS: u32 = 6;
/// Adjacent steps accepted on each side for clock skew.
pub const SKEW_WINDOW: u64 = 1;

/// The HOTP value for `secret` at `counter` (RFC 4226 §5.3).
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
	let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
	let mac = hmac::sign(&key, &counter.to_be_bytes());
	let digest = mac.as_ref();
	// Dynamic truncation: low 4 bits of the last byte pick a 4-byte offset.
	let offset = (digest[digest.len() - 1] & 0x0f) as usize;
	let binary = (u32::from(digest[offset] & 0x7f) << 24)
		| (u32::from(digest[offset + 1]) << 16)
		| (u32::from(digest[offset + 2]) << 8)
		| u32::from(digest[offset + 3]);
	binary % 10u32.pow(digits)
}

/// The current TOTP code for `secret` at `now_secs`.
pub fn totp(secret: &[u8], now_secs: u64) -> u32 {
	hotp(secret, now_secs / STEP_SECONDS, DIGITS)
}

/// Whether `code` is valid for `secret` at `now_secs`, accepting `SKEW_WINDOW`
/// adjacent steps. Compared in constant time over the formatted digits.
pub fn verify(secret: &[u8], code: u32, now_secs: u64) -> bool {
	let counter = now_secs / STEP_SECONDS;
	let expected = format!("{code:0width$}", width = DIGITS as usize);
	let low = counter.saturating_sub(SKEW_WINDOW);
	(low..=counter + SKEW_WINDOW).any(|step| {
		let candidate = format!(
			"{:0width$}",
			hotp(secret, step, DIGITS),
			width = DIGITS as usize
		);
		constant_time::eq(candidate.as_bytes(), expected.as_bytes())
	})
}

/// Encode bytes as an RFC 4648 base32 string (no padding).
pub fn encode_base32(bytes: &[u8]) -> String {
	const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let mut out = String::new();
	let mut bits = 0u32;
	let mut nbits = 0u32;
	for &byte in bytes {
		bits = (bits << 8) | u32::from(byte);
		nbits += 8;
		while nbits >= 5 {
			nbits -= 5;
			out.push(ALPHABET[((bits >> nbits) & 0x1f) as usize] as char);
		}
	}
	if nbits > 0 {
		out.push(ALPHABET[((bits << (5 - nbits)) & 0x1f) as usize] as char);
	}
	out
}

/// Decode an RFC 4648 base32 secret (no padding required, case-insensitive).
pub fn decode_base32_secret(secret: &str) -> Option<Vec<u8>> {
	const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let mut bits = 0u32;
	let mut nbits = 0u32;
	let mut out = Vec::new();
	for ch in secret.bytes() {
		if ch == b'=' || ch == b' ' {
			continue;
		}
		let value = ALPHABET
			.iter()
			.position(|&a| a == ch.to_ascii_uppercase())? as u32;
		bits = (bits << 5) | value;
		nbits += 5;
		if nbits >= 8 {
			nbits -= 8;
			out.push((bits >> nbits) as u8);
		}
	}
	Some(out)
}

#[cfg(test)]
mod tests;
