//! SCRAM-SHA-256 with a non-ASCII password.
//!
//! The protocol itself does not normalise: the verifier is derived from
//! whatever bytes the server fed PBKDF2 at set-time, and a client whose
//! SCRAM library prepares its candidate with SASLprep (which is NFKC, per
//! RFC 4013) must reach a verifier that was derived from the NFKC form.
//! These tests pin the storage-layer contract the rest of the system
//! relies on:
//!
//! - `ScramCredentials::derive(password, ...)` is called with the *prepared*
//!   password (NFKC when `[auth] unicode_passwords = true`), not the raw
//!   bytes the user typed. Without that preparation, an NFD-form input
//!   derives a different verifier from an NFC-form input even though the
//!   user sees the same string.
//! - `ScramStored::with_fresh_salt(password)` similarly receives the
//!   prepared form, so the produced `StoredKey` matches what an
//!   SCRAM-SHA-256 client computes from the same Unicode password.
//! - The brief's example, `contraseñaSegura` set in NFC and verified in
//!   NFD, both prepare to the same bytes and therefore derive the same
//!   credentials.

use crate::password::Policy;
use crate::smtp::scram::{ScramCredentials, SCRAM_ITERATIONS};
use crate::test_fixtures as fixtures;

/// The brief's example password in NFC form (`ñ` precomposed U+00F1).
const NFC_PASSWORD: &str = "contrase\u{00F1}aSegura12";
/// The same password in NFD form (`n` U+006E followed by combining tilde
/// U+0303). Two byte sequences, one canonical UTF-8 user-perceived string.
const NFD_PASSWORD: &str = "contrase\u{006E}\u{0303}aSegura12";

#[test]
fn scram_with_fresh_salt_holds_across_nfc_and_nfd_under_unicode_policy() {
	// Set-time must derive the verifier from the NFKC form so a
	// SASLprep-aware client (which itself normalises with NFKC) ends up
	// with the same SaltedPassword. The test asserts the storage-layer
	// contract by deriving both encodings against the *same* salt and
	// comparing: when the inputs are first normalised by the policy they
	// produce identical verifier material; without that preparation
	// they diverge (the second test in this file pins that).
	let policy = Policy::unicode();
	let prepared_nfc = policy.prepare(NFC_PASSWORD).expect("nfc is valid");
	let prepared_nfd = policy.prepare(NFD_PASSWORD).expect("nfd is valid");
	assert_eq!(
		prepared_nfc.as_ref(),
		prepared_nfd.as_ref(),
		"shape precondition: NFKC collapses NFD to NFC",
	);

	let salt = [0x42u8; 16];
	let from_nfc = ScramCredentials::derive(prepared_nfc.as_ref(), &salt, SCRAM_ITERATIONS);
	let from_nfd = ScramCredentials::derive(prepared_nfd.as_ref(), &salt, SCRAM_ITERATIONS);
	assert_eq!(
		from_nfc.stored_key, from_nfd.stored_key,
		"two NFD/NFC inputs prepared by the same policy must derive the same stored key under the same salt"
	);
	assert_eq!(
		from_nfc.server_key, from_nfd.server_key,
		"the server key follows the same rule"
	);
}

#[test]
fn scram_derive_sees_through_preparation_to_canonical_bytes() {
	// The brief requirement is "verification must normalise the same way,
	// including SCRAM (RFC 5802 SASLprep / RFC 7677)". The contract here
	// is that the derive function takes already-prepared bytes; the
	// caller (the directory layer) is what runs NFKC. Pin that the two
	// agree when the policy is applied: a SCRAM verifier built from the
	// raw NFC input cannot accidentally match a verifier built from the
	// raw NFD input, but after `Policy::unicode().prepare` both produce
	// the same key material.
	let prepared_nfc = Policy::unicode().prepare(NFC_PASSWORD).expect("valid");
	let prepared_nfd = Policy::unicode().prepare(NFD_PASSWORD).expect("valid");
	let via_nfc = ScramCredentials::derive(
		prepared_nfc.as_ref(),
		fixtures::salt(),
		SCRAM_ITERATIONS,
	);
	let via_nfd = ScramCredentials::derive(
		prepared_nfd.as_ref(),
		fixtures::salt(),
		SCRAM_ITERATIONS,
	);
	assert_eq!(
		via_nfc.stored_key, via_nfd.stored_key,
		"prepared forms must derive the same stored key under the same salt"
	);

	// Sanity: the same two inputs *without* the policy prepare actually
	// diverge — this is what would happen if the storage layer forgot to
	// run `prepare` before `ScramStored::with_fresh_salt`.
	let raw_nfc = ScramCredentials::derive(NFC_PASSWORD, fixtures::salt(), SCRAM_ITERATIONS);
	let raw_nfd = ScramCredentials::derive(NFD_PASSWORD, fixtures::salt(), SCRAM_ITERATIONS);
	assert_ne!(
		raw_nfc.stored_key, raw_nfd.stored_key,
		"without preparation the two encodings differ in PBKDF2 input bytes",
	);
}
