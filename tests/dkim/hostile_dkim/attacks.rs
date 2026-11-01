//! Single-variable mutations isolate syntax, body, and signature failures.

use super::harness::*;
use super::support::*;
use epistle::dkim::DkimOutcome::{Fail, Pass, PermError};

const BASE: &str = "ed25519-relaxed-relaxed-mixed";

#[test]
fn exact_canonical_body_length_passes() {
	case("length-equal", Pass, 1);
}

#[test]
// RFC 6376 sections 3.5 and 8.2 permit rejecting partly signed bodies.
fn signed_prefix_with_unsigned_suffix_fails_before_dns() {
	case("length-short", Fail, 0);
}

#[test]
fn appended_content_after_an_exact_length_fails_before_dns() {
	let mut raw = message("length-equal");
	raw.extend_from_slice(b"Pay the attacker\r\n");
	expect_dkim(
		raw,
		Dns::dkim("length-equal"),
		Fail,
		Some("example.test"),
		0,
	);
}

#[test]
fn length_beyond_canonical_body_is_permerror() {
	case("length-long", PermError, 0);
}

#[test]
fn zero_length_cannot_authenticate_a_nonempty_body() {
	case("length-zero", Fail, 0);
}

#[test]
fn zero_length_authenticates_an_empty_relaxed_body() {
	case("length-zero-empty", Pass, 1);
}

#[test]
fn h_omitting_from_is_permerror_before_dns() {
	expect_dkim(message("no-from"), Dns::dkim("no-from"), PermError, None, 0);
}

#[test]
fn oversigned_from_rejects_a_prepended_duplicate() {
	let mut raw = b"From: attacker@evil.test\r\n".to_vec();
	raw.extend_from_slice(&message(BASE));
	expect_dkim(raw, Dns::dkim(BASE), Fail, Some("example.test"), 1);
}

#[test]
fn altered_body_hash_fails_before_dns() {
	use base64::Engine;
	let hash = base64::engine::general_purpose::STANDARD.encode([0; 32]);
	expect_dkim(
		tag(&message(BASE), "bh", &hash),
		Dns::dkim(BASE),
		Fail,
		Some("example.test"),
		0,
	);
}

#[test]
fn truncated_b_with_valid_base64_fails_crypto() {
	use base64::Engine;
	let raw = message(BASE);
	let wire = std::str::from_utf8(&raw).unwrap();
	let value = wire
		.split(" b=")
		.nth(1)
		.unwrap()
		.split("\r\n")
		.next()
		.unwrap();
	let b64 = base64::engine::general_purpose::STANDARD;
	let mut signature = b64.decode(value).expect("fixture b=");
	assert_eq!(signature.len(), 64);
	signature.truncate(60);
	expect_dkim(
		tag(&raw, "b", &b64.encode(signature)),
		Dns::dkim(BASE),
		Fail,
		Some("example.test"),
		1,
	);
}

#[test]
fn invalid_base64_b_is_permerror_before_dns() {
	expect_dkim(
		tag(&message(BASE), "b", "%%%?"),
		Dns::dkim(BASE),
		PermError,
		None,
		0,
	);
}

#[test]
fn well_formed_wrong_b_fails_crypto() {
	use base64::Engine;
	let signature = base64::engine::general_purpose::STANDARD.encode([0; 64]);
	expect_dkim(
		tag(&message(BASE), "b", &signature),
		Dns::dkim(BASE),
		Fail,
		Some("example.test"),
		1,
	);
}

#[test]
fn short_length_is_checked_even_if_full_body_hash_matches() {
	case("length-short-fullhash", Fail, 0);
}

#[test]
fn zero_length_is_checked_even_if_full_body_hash_matches() {
	case("length-zero-fullhash", Fail, 0);
}
