//! Tests for the key an ARC header is verified against.
//!
//! The algorithm the header declares has to govern both the primitive and
//! the shape of the key, and the key type the record publishes has to agree
//! with it.

use super::super::key::KeyRecord;
use crate::dkim::Algorithm;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{KeyPair, RsaKeyPair};

/// The RSA key the RSA tests sign with: the one DKIM's own tests use.
const RSA_TEST_KEY: &str = include_str!("../../dkim/test_rsa_key.pem");

/// The RSA key pair the RSA tests sign with.
pub(super) fn rsa_key_pair() -> RsaKeyPair {
	let body: String = RSA_TEST_KEY
		.lines()
		.filter(|line| !line.starts_with("-----"))
		.collect::<Vec<_>>()
		.join("");
	let der = BASE64.decode(body).expect("base64 body");
	RsaKeyPair::from_pkcs8(&der).expect("RSA key")
}

/// The DNS record that publishes `key`, in the form a sender writes it: the
/// SubjectPublicKeyInfo of the RSA key, base64 encoded (RFC 6376 section
/// 3.6.1).
pub(super) fn rsa_record(key: &RsaKeyPair) -> String {
	let spki = crate::dkim::spki_for_rsa(key.public_key().as_ref());
	format!("v=DKIM1; k=rsa; p={}", BASE64.encode(spki))
}

/// The DNS record that publishes an Ed25519 key of 32 bytes.
pub(super) fn ed25519_record(key: &[u8]) -> String {
	format!("v=DKIM1; k=ed25519; p={}", BASE64.encode(key))
}

/// A PKCS#1 `RSAPublicKey` body whose modulus is exactly `bits` bits long,
/// with the public exponent 65537.
fn rsa_public_key_with_modulus_bits(bits: usize) -> Vec<u8> {
	let len = bits.div_ceil(8);
	let top_bits = bits - (len - 1) * 8;
	let mut modulus = vec![0xffu8; len];
	// The top byte holds the last `top_bits` bits of the modulus.
	modulus[0] = 0xffu8 >> (8 - top_bits);
	// A DER integer carries a zero byte in front of the modulus when its top
	// bit is set, to keep the integer positive.
	let sign = if modulus[0] & 0x80 != 0 {
		vec![0x00]
	} else {
		Vec::new()
	};

	let mut body = Vec::new();
	body.push(0x02);
	der_len(&mut body, sign.len() + len);
	body.extend_from_slice(&sign);
	body.extend_from_slice(&modulus);
	body.push(0x02);
	body.push(0x03);
	body.extend_from_slice(&[0x01, 0x00, 0x01]);

	let mut sequence = Vec::new();
	sequence.push(0x30);
	der_len(&mut sequence, body.len());
	sequence.extend_from_slice(&body);
	sequence
}

/// Append a DER length to `out`, in the short form when it fits in seven
/// bits and in the long form otherwise.
fn der_len(out: &mut Vec<u8>, len: usize) {
	if len < 0x80 {
		out.push(len as u8);
		return;
	}
	if len <= 0xff {
		out.push(0x81);
		out.push(len as u8);
		return;
	}
	out.push(0x82);
	out.push((len >> 8) as u8);
	out.push(len as u8);
}

/// The record that publishes an RSA key whose modulus is `bits` bits long.
fn rsa_record_with_modulus_bits(bits: usize) -> String {
	let pkcs1 = rsa_public_key_with_modulus_bits(bits);
	let spki = crate::dkim::spki_for_rsa(&pkcs1);
	format!("v=DKIM1; k=rsa; p={}", BASE64.encode(spki))
}

#[test]
fn a_record_without_a_key_type_is_an_rsa_record() {
	// RFC 6376 section 3.6.1 makes rsa the default when the tag is absent.
	let spki = crate::dkim::spki_for_rsa(&rsa_public_key_with_modulus_bits(2048));
	let record = format!("v=DKIM1; p={}", BASE64.encode(spki));
	let record = KeyRecord::first(&[record]).expect("record");
	assert!(
		record.verification_key(Algorithm::RsaSha256).is_ok(),
		"a record without a k= tag is an RSA record"
	);
}

#[test]
fn an_unknown_key_type_is_ignored() {
	// RFC 6376 section 3.6.1 tells the verifier to ignore such a record.
	let record = "v=DKIM1; k=dsa; p=AAAA";
	assert!(KeyRecord::first(&[record.to_string()]).is_err());
}

#[test]
fn a_string_without_a_key_is_not_a_key_record() {
	assert!(KeyRecord::first(&["v=DKIM1".to_string()]).is_err());
}

#[test]
fn a_string_without_a_key_does_not_hide_the_record_that_has_one() {
	let record = rsa_record_with_modulus_bits(2048);
	let texts = vec!["v=DKIM1".to_string(), record];
	assert!(KeyRecord::first(&texts).is_ok());
}

#[test]
fn the_first_record_that_publishes_a_key_is_the_one_used() {
	let first = rsa_record_with_modulus_bits(2048);
	let second = rsa_record_with_modulus_bits(2048);
	let texts = vec![first, second];
	assert!(KeyRecord::first(&texts).is_ok());
}

#[test]
fn an_ed25519_header_refuses_a_record_that_publishes_an_rsa_key() {
	let record = KeyRecord::first(&[rsa_record_with_modulus_bits(2048)]).expect("record");
	assert!(
		record.verification_key(Algorithm::Ed25519Sha256).is_err(),
		"an Ed25519 header must not use an RSA key"
	);
}

#[test]
fn an_rsa_header_refuses_a_record_that_publishes_an_ed25519_key() {
	let record = KeyRecord::first(&[ed25519_record(&[7u8; 32])]).expect("record");
	assert!(
		record.verification_key(Algorithm::RsaSha256).is_err(),
		"an RSA header must not use an Ed25519 key"
	);
}

#[test]
fn an_ed25519_key_of_the_wrong_length_is_refused() {
	let record = KeyRecord::first(&[ed25519_record(&[7u8; 31])]).expect("record");
	assert!(
		record.verification_key(Algorithm::Ed25519Sha256).is_err(),
		"an Ed25519 key is 32 bytes"
	);
}

#[test]
fn an_rsa_key_of_a_modulus_below_1024_bits_is_refused() {
	let record = KeyRecord::first(&[rsa_record_with_modulus_bits(1023)]).expect("record");
	assert!(
		record.verification_key(Algorithm::RsaSha256).is_err(),
		"a modulus below 1024 bits is refused"
	);
}

#[test]
fn an_rsa_key_of_a_modulus_of_1024_bits_is_accepted() {
	let record = KeyRecord::first(&[rsa_record_with_modulus_bits(1024)]).expect("record");
	assert!(
		record.verification_key(Algorithm::RsaSha256).is_ok(),
		"a modulus of 1024 bits is the smallest this verifier accepts"
	);
}

#[test]
fn a_record_that_claims_an_rsa_key_and_publishes_another_shape_is_refused() {
	// The record says k=rsa, but what it publishes is the 32 bytes of an
	// Ed25519 key.
	let record = KeyRecord::first(&[format!("v=DKIM1; k=rsa; p={}", BASE64.encode([9u8; 32]))])
		.expect("record");
	assert!(
		record.verification_key(Algorithm::RsaSha256).is_err(),
		"a key that is not an RSA key is refused"
	);
}
