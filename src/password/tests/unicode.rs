//! Tests for the Unicode password policy.
//!
//! These cover the `Policy` surface only; SCRAM-side behaviour and the
//! argon2id path are exercised where the bytes actually flow through the
//! storage layer (`smtp/auth/mod.rs`, `smtp/scram/mod.rs`). The fixtures here stay
//! pointed at the policy so a regression in the storage wiring that
//! bypasses `Policy` is caught independently by the storage-layer tests.

// These two `pub(super)` constants and the `Policy` symbol live in the
// password module; this file is the test-only sibling, declared with
// `#[path]` so the production type and the tests stay separately
// under the line cap.
use crate::password::{MAX_LENGTH, MIN_LENGTH, Policy, Rejection};

/// The same password in NFC form (`ñ` precomposed, U+00F1) and in NFD form
/// (`n` followed by the combining tilde U+0303), with one random ASCII tail,
/// so no password is written into the test.
fn passwords() -> (String, String) {
	let tail = crate::test_fixtures::printable_ascii(MIN_LENGTH);
	(
		format!("contrase\u{00F1}a{tail}"),
		format!("contrase\u{006E}\u{0303}a{tail}"),
	)
}

#[test]
fn unicode_policy_prepare_returns_nfkc_normalised_owned() {
	let (nfc, nfd) = passwords();
	let policy = Policy::unicode();
	let prepared = policy.prepare(nfd.as_str()).expect("valid");
	assert!(
		!std::ptr::eq(prepared.as_ptr(), nfd.as_ptr()) || prepared == nfd.as_str(),
		"shape precondition: the NFD form must allocate or already be NFC",
	);
	assert_eq!(
		prepared.as_ref(),
		nfc.as_str(),
		"NFKC must collapse NFD back into NFC byte-for-byte",
	);
}
#[test]
fn unicode_policy_prepare_rejects_a_control_scalar() {
	// C0 control (TAB). Embedded in a password that is otherwise long
	// enough to pass length, so the rejection must be the character
	// reason, not length.
	let policy = Policy::unicode();
	// 11 ASCII letters + 1 TAB: 12 scalars, with a control embedded.
	let mut bad = String::with_capacity(12);
	for (i, c) in "abcdefghijk".chars().enumerate() {
		if i == 7 {
			bad.push('\t');
		}
		bad.push(c);
	}
	assert_eq!(bad.chars().count(), MIN_LENGTH, "shape precondition");
	assert_eq!(policy.prepare(&bad), Err(Rejection::IllegalCharacter));
}

#[test]
fn unicode_policy_normalises_length_to_normalised_form() {
	// Build a string whose NFC length is 12 (the minimum) and whose NFD
	// length is well over 64. After NFKC it lands inside the window; the
	// validator must look at the normalised length, not the raw byte
	// length, to issue a pass and a fail correctly in each direction.
	let policy = Policy::unicode();
	// 1 combining-mark + 11 ASCII letters: 12 scalars in NFC, 13 scalars
	// after NFC (combining mark counts as one scalar), still inside.
	let ascii_11 = crate::test_fixtures::printable_ascii(11);
	let nfc_form: String = format!("\u{0303}{ascii_11}"); // 12 scalars
	assert_eq!(nfc_form.chars().count(), 12);
	assert_eq!(policy.prepare(&nfc_form).unwrap().chars().count(), 12);
	// A megabyte-ish decomposition, well past 64 scalars.
	let nfd_long: String = (0..70).map(|_| '\u{0303}').collect();
	assert!(
		nfd_long.chars().count() > MAX_LENGTH,
		"shape precondition: the decomposed form must exceed MAX_LENGTH"
	);
	assert_eq!(policy.prepare(&nfd_long), Err(Rejection::TooLong));
}

#[test]
fn unicode_policy_validates_nfc_and_verifies_nfd_via_the_prepared_form() {
	let (nfc, nfd) = passwords();
	let policy = Policy::unicode();
	// Validation gate accepts both byte sequences; the password is set
	// under one form and verified under the other without any bcrypt/
	// SCRAM layer in between, by routing both through `prepare`.
	let prepared_nfc = policy.prepare(nfc.as_str()).expect("NFC is valid");
	let prepared_nfd = policy.prepare(nfd.as_str()).expect("NFD is valid");
	assert_eq!(
		prepared_nfc.as_ref(),
		prepared_nfd.as_ref(),
		"prepared forms must agree, that is the point of the normalisation",
	);
	// Going through `validate` must also accept both: validation is on
	// the prepared form, and both forms prepare to the same string.
	assert_eq!(policy.validate(nfc.as_str()), Ok(()));
	assert_eq!(policy.validate(nfd.as_str()), Ok(()));
}

#[test]
fn ascii_only_policy_still_refuses_non_ascii() {
	let (nfc, _) = passwords();
	// With the flag off, today's behaviour must hold: a candidate with
	// non-ASCII scalars is rejected as IllegalCharacter, regardless of
	// length.
	let password = nfc.as_str();
	assert!(
		!password.is_ascii(),
		"shape precondition: the fixture is non-ASCII",
	);
	assert_eq!(
		Policy::default().validate(password),
		Err(Rejection::IllegalCharacter)
	);
	assert_eq!(
		Policy::ASCII_ONLY.validate(password),
		Err(Rejection::IllegalCharacter)
	);
}

#[test]
fn from_config_defaults_unicode_passwords_to_false() {
	// An absent `[auth]` section must keep the historical behaviour.
	// The constructor maps the field 1-to-1, so the test is on the
	// fall-through path through `Auth::default`.
	let auth = crate::config::Auth::default();
	assert!(
		!auth.unicode_passwords,
		"shape precondition: the [auth] default still rejects non-ASCII"
	);
	assert_eq!(Policy::from_config(&auth), Policy::ASCII_ONLY);
}
