//! Unit tests for the keyword validator and serde round-trip.

use super::*;
use serde_json::json;

#[test]
fn accepts_a_basic_keyword() {
	assert!(validate("custom").is_ok());
	assert!(validate("$Junk").is_ok());
	assert!(validate("x-custom").is_ok());
}

#[test]
fn rejects_an_empty_keyword() {
	assert!(validate("").is_err());
}

#[test]
fn rejects_a_keyword_longer_than_64_bytes() {
	let long = "a".repeat(MAX_KEYWORD_BYTES + 1);
	assert!(validate(&long).is_err());
	let exactly = "a".repeat(MAX_KEYWORD_BYTES);
	assert!(validate(&exactly).is_ok());
}

#[test]
fn rejects_a_keyword_with_a_backslash() {
	assert!(validate("\\Custom").is_err());
	assert!(validate("\\Junk").is_err());
}

#[test]
fn rejects_a_keyword_with_a_space_or_atom_special() {
	for byte in [' ', '(', ')', '{', '%', '*', '"', ']', '\\'] {
		let token = format!("custom{byte}end");
		assert!(validate(&token).is_err(), "{token:?} should be rejected");
	}
}

#[test]
fn rejects_a_keyword_with_a_control_byte() {
	// 0x01 (SOH) is a control byte and must be rejected.
	let bad = "x\x01y";
	assert!(validate(bad).is_err());
}

#[test]
fn rejects_a_keyword_with_a_del_byte() {
	// 0x7F (DEL) is the high-bit-set control byte that
	// `is_ascii_control` covers; a regression that swaps to a
	// printable-ASCII check alone must be caught here.
	let bad = "x\x7fy";
	assert!(validate(bad).is_err());
}

/// Bytes with the high bit set are not part of the IMAP atom
/// production: a single non-ASCII byte anywhere in the keyword is
/// enough to refuse it. The pair below pins the boundary.
#[test]
fn rejects_a_keyword_with_a_high_bit_byte() {
	// The accented e (U+00E9, encoded as two UTF-8 bytes starting
	// with 0xC3) sits inside "café". It must be refused; the
	// bare-ASCII "cafe" must be accepted just inside the limit.
	let accent = "caf\u{e9}";
	let plain = "cafe";
	assert!(validate(accent).is_err(), "caf\u{e9} must be refused");
	assert!(validate(plain).is_ok(), "cafe must be accepted");
}

#[test]
fn serde_round_trip_preserves_case() {
	let kw = Keyword::new("$Junk").expect("valid");
	let encoded = serde_json::to_string(&kw).expect("encode");
	// The shape is a JSON string, not an object, matches the documented
	// format and keeps the file backwards-compatible with older readers.
	assert_eq!(encoded, "\"$Junk\"");
	let decoded: Keyword = serde_json::from_str(&encoded).expect("decode");
	assert_eq!(decoded, kw);
}

#[test]
fn serde_deserialize_rejects_an_invalid_token() {
	// Sidecar written with a bad token (e.g. by a regression) refuses
	// to load rather than silently re-introducing a value that failed
	// the validator.
	let raw = json!("contains space");
	let result: Result<Keyword, _> = serde_json::from_value(raw);
	assert!(result.is_err());
}

#[test]
fn equality_is_case_insensitive() {
	let kw = Keyword::new("$Junk").expect("valid");
	assert!(kw.matches("$Junk"));
	assert!(kw.matches("$junk"));
	assert!(kw.matches("$JUNK"));
	assert!(!kw.matches("$notjunk"));
}

#[test]
fn junk_predicates_match_case_insensitively() {
	let upper = Keyword::new("$JUNK").expect("valid");
	let mixed = Keyword::new("$Junk").expect("valid");
	let other = Keyword::new("$Forwarded").expect("valid");
	assert!(upper.is_junk());
	assert!(mixed.is_junk());
	assert!(!other.is_junk());
	assert!(!other.is_not_junk());
	assert!(Keyword::new("$NOTJUNK").expect("valid").is_not_junk());
}
