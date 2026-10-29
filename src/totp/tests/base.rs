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
