//! Time-based one-time passwords (TOTP, RFC 6238) for two-factor auth.
//!
//! The shared secret is HMAC'd with a time counter to derive a short numeric
//! code; verification accepts a small window of adjacent steps for clock skew.
//! HMAC-SHA1 is the de-facto standard authenticator-app algorithm.

use ring::hmac;

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
		constant_time_eq(candidate.as_bytes(), expected.as_bytes())
	})
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

/// Length-aware constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
	use super::*;

	// RFC 6238 Appendix B uses the ASCII secret "12345678901234567890".
	const SECRET: &[u8] = b"12345678901234567890";

	#[test]
	fn hotp_matches_rfc4226_vectors() {
		// RFC 4226 Appendix D, 6-digit values for counters 0..3.
		assert_eq!(hotp(SECRET, 0, 6), 755224);
		assert_eq!(hotp(SECRET, 1, 6), 287082);
		assert_eq!(hotp(SECRET, 2, 6), 359152);
		assert_eq!(hotp(SECRET, 3, 6), 969429);
	}

	#[test]
	fn totp_at_known_time() {
		// At T=59s the step counter is 1 → the HOTP(1) value.
		assert_eq!(totp(SECRET, 59), hotp(SECRET, 1, 6));
	}

	#[test]
	fn verify_accepts_current_and_skewed_codes() {
		let now = 1_000_000u64;
		let code = totp(SECRET, now);
		assert!(verify(SECRET, code, now));
		// One step earlier/later is accepted (clock skew).
		assert!(verify(SECRET, code, now + STEP_SECONDS));
		assert!(verify(SECRET, code, now.saturating_sub(STEP_SECONDS)));
		// Two steps away is rejected.
		assert!(!verify(SECRET, code, now + 3 * STEP_SECONDS));
	}

	#[test]
	fn verify_rejects_wrong_code() {
		let now = 1_000_000u64;
		let wrong = (totp(SECRET, now) + 1) % 1_000_000;
		assert!(!verify(SECRET, wrong, now));
	}

	#[test]
	fn base32_decode_roundtrips_known_secret() {
		// "JBSWY3DPEHPK3PXP" is the base32 of "Hello!\xde\xad\xbe\xef".
		let decoded = decode_base32_secret("JBSWY3DPEHPK3PXP").expect("decode");
		assert_eq!(&decoded[..5], b"Hello");
		// Lowercase and spacing are tolerated.
		assert_eq!(
			decode_base32_secret("jbsw y3dp"),
			decode_base32_secret("JBSWY3DP")
		);
		// Invalid characters fail.
		assert!(decode_base32_secret("0189!").is_none());
	}
}
