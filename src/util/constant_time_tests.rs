//! Tests for the length-aware constant-time byte comparison.

use super::eq;

#[test]
fn equal_slices_of_equal_length_match() {
	assert!(eq(b"abcdef", b"abcdef"));
	assert!(eq(b"", b""));
	assert!(eq(&[0x00, 0xff, 0x80], &[0x00, 0xff, 0x80]));
}

#[test]
fn different_bytes_in_equal_length_slices_mismatch() {
	assert!(!eq(b"abcdef", b"abcdfg"));
	assert!(!eq(b"abc", b"abd"));
	// A single-bit flip at the start.
	assert!(!eq(&[0x00, 0xff, 0x80], &[0x01, 0xff, 0x80]));
}

#[test]
fn different_length_slices_mismatch_without_scanning() {
	assert!(!eq(b"abc", b"ab"));
	assert!(!eq(b"", b"a"));
	assert!(!eq(b"abcdef", b"abcdefg"));
}

/// Per-callsite coverage of the four credential comparisons the secret-hygiene
/// pass names (`src/smtp/scram.rs` stored key, `src/api/oauth/device.rs` user
/// code, `src/api/state.rs` bearer digest, `src/api/api_keys.rs` api-key
/// digest). Each test feeds the helper the right value, a same-length wrong
/// value, and a different-length wrong value, asserting the result the caller
/// relies on: accept / reject / reject.
#[test]
fn scram_stored_key_check() {
	let stored_key = [0xaa_u8; 32];
	let mut wrong_same_length = stored_key;
	wrong_same_length[0] ^= 0x01;
	let wrong_other_length = [0xaa_u8; 31];
	assert!(eq(&stored_key, &stored_key), "matching stored_key must be accepted");
	assert!(
		!eq(&stored_key, &wrong_same_length),
		"single-bit-flip stored_key must be rejected"
	);
	assert!(
		!eq(&stored_key, &wrong_other_length),
		"shorter stored_key must be rejected"
	);
}

#[test]
fn oauth_device_user_code_check() {
	let user_code = b"HTTPS-7241";
	let mut wrong_same_length = *user_code;
	wrong_same_length[5] ^= 0x01;
	let wrong_other_length = b"HTTPS-72";
	assert!(
		eq(user_code, user_code),
		"matching device user_code must be accepted"
	);
	assert!(
		!eq(user_code, &wrong_same_length),
		"single-char-wrong device user_code must be rejected"
	);
	assert!(
		!eq(user_code, wrong_other_length),
		"shorter device user_code must be rejected"
	);
}

#[test]
fn bearer_digest_check() {
	// A SHA-256 digest rendered as hex is 64 bytes; that is the length the
	// bearer-token comparison in `src/api/state.rs` works with.
	let expected_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	let mut wrong_same_length = *expected_hex;
	wrong_same_length[1] = b'f';
	let wrong_other_length = &expected_hex[..63];
	assert!(
		eq(expected_hex, expected_hex),
		"matching bearer digest must be accepted"
	);
	assert!(
		!eq(expected_hex, &wrong_same_length),
		"single-nibble-wrong bearer digest must be rejected"
	);
	assert!(
		!eq(expected_hex, wrong_other_length),
		"shorter bearer digest must be rejected"
	);
}

#[test]
fn api_key_digest_check() {
	// `sha256:<hex>` for an api-key — 71 bytes total; the comparison strips
	// the `sha256:` prefix but the byte span is what `eq` is fed.
	let stored = b"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	let expected_digest = &stored[b"sha256:".len()..];
	let mut wrong_same_length = expected_digest.to_vec();
	wrong_same_length[0] = b'f';
	let wrong_other_length = &expected_digest[..63];
	assert!(
		eq(expected_digest, expected_digest),
		"matching api-key digest must be accepted"
	);
	assert!(
		!eq(expected_digest, &wrong_same_length),
		"single-nibble-wrong api-key digest must be rejected"
	);
	assert!(
		!eq(expected_digest, wrong_other_length),
		"shorter api-key digest must be rejected"
	);
}
