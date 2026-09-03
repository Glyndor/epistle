//! Tests for the TOTP suffix split in `Directory::authenticate`.
//!
//! These tests pin the safety property that `totp_strip` does not call
//! `str::split_at` on a byte offset that is not on a UTF-8 character
//! boundary. They exist as a sibling module rather than inline so the
//! 450-line cap on `directory.rs` is not threatened; the body lives
//! here next to the other `directory_*_tests.rs` files.
//!
//! The control test exercises two shapes of multibyte tail. The first
//! is a set of illustrative suffixes (e.g. `"correct-horse\u{00e9}"`,
//! `"p\u{00e4}ssw\u{00f6}rd\u{00fc}"`); they are non-ASCII and the fix
//! must handle them. The second is a constructed trigger where the
//! byte-length split lands inside the last multibyte character; with
//! the old code this is the case that panics, and it is the only one
//! that proves the boundary check actually runs.

use super::*;
use crate::smtp::auth::tests::{fixture_password, hash};

fn directory_with_totp(secret: &[u8]) -> Directory {
	let password = fixture_password().to_string();
	Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([("alice".to_string(), hash(&password))])
	.with_totp([("alice".to_string(), crate::totp::encode_base32(secret))])
}

#[test]
fn a_password_ending_in_a_multibyte_character_does_not_panic_with_totp() {
	let directory = directory_with_totp(&uuid::Uuid::now_v7().into_bytes());
	let fixture = fixture_password().to_string();

	// Illustrative suffixes. The byte-length split happens to
	// land on a UTF-8 boundary here, so the old code never panicked on
	// these exact strings, but they exercise the same non-ASCII path
	// that the fix now closes, and must continue to return `None`
	// without panicking.
	let illustrative = [
		(
			"two-byte trailing char after ASCII password",
			format!("{fixture}correct-horse\u{00e9}"),
		),
		(
			"two-byte trailing char after non-ASCII password",
			format!("{fixture}p\u{00e4}ssw\u{00f6}rd\u{00fc}"),
		),
	];
	for (label, candidate) in illustrative {
		let outcome = directory.authenticate("alice", &candidate, crate::config::Protocol::Api);
		assert!(
			outcome.is_none(),
			"{label}: expected no auth, got {outcome:?}"
		);
	}

	// The constructed triggers. In each of these the trailing six bytes
	// straddle a multibyte character so the byte-length split lands on
	// a continuation byte; with the old code these panicked, with the
	// fix they must return `None`.
	//
	// `"1234567\u{00e4}xxxxx"` (14 bytes): the `ä` occupies bytes 7..9,
	// so `len - 6 = 8` lands inside the character.
	//
	// `"abcd\u{00e4}efghi"` (11 bytes): the `ä` occupies bytes 4..6, so
	// `len - 6 = 5` lands inside the character.
	let triggers = [
		(
			"two-byte char whose second byte is at len-6",
			format!("{fixture}1234567\u{00e4}xxxxx"),
		),
		(
			"two-byte char whose second byte is at len-6 (shorter)",
			format!("{fixture}abcd\u{00e4}efghi"),
		),
	];
	for (label, candidate) in triggers {
		let outcome = directory.authenticate("alice", &candidate, crate::config::Protocol::Api);
		assert!(
			outcome.is_none(),
			"{label}: expected no auth, got {outcome:?}"
		);
	}
}

#[test]
fn a_valid_code_after_a_multibyte_password_still_authenticates() {
	// Non-ASCII base password plus a real current TOTP code must still
	// authenticate. The hash is computed for the multibyte base so the
	// primary password check matches the candidate we present. The
	// secret is minted per call so no literal reaches the directory's
	// TOTP slot or the code derivation; the same bytes feed both paths.
	let secret = uuid::Uuid::now_v7().into_bytes();
	let multibyte_base = "p\u{00e4}ssw\u{00f6}rd".to_string();
	let directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([("alice".to_string(), hash(&multibyte_base))])
	.with_totp([("alice".to_string(), crate::totp::encode_base32(&secret))]);

	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let code = crate::totp::totp(&secret, now);
	let candidate = format!("{multibyte_base}{code:06}");
	assert_eq!(
		directory
			.authenticate("alice", &candidate, crate::config::Protocol::Api)
			.as_deref(),
		Some("alice"),
		"the multibyte-password fixture must accept a real TOTP code",
	);
}

#[test]
fn a_six_digit_tail_that_is_not_all_digits_is_not_a_code() {
	// The tail `x12345` is six bytes long but only five of them are digits.
	// The old split happily sliced the password at a byte boundary, then
	// `code.parse()` returned `Err` and the call silently failed. The fix
	// should reject the candidate as a code (return `None`) without parsing
	// anything, and crucially without panicking on the boundary.
	let directory = directory_with_totp(&uuid::Uuid::now_v7().into_bytes());
	let candidate = format!("{}{}", fixture_password(), "secretx12345");
	assert!(
		directory
			.authenticate("alice", &candidate, crate::config::Protocol::Api)
			.is_none()
	);
}
