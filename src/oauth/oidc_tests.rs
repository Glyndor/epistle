//! Tests for OIDC JWKS parsing and JWK→key conversion. Keys are generated with
//! ring so nothing touches the network.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

/// Build a JWKS JSON document with one EC P-256 key from a ring public point.
fn ec_jwks(public_point: &[u8], kid: &str) -> String {
	// Uncompressed point: 0x04 ‖ x(32) ‖ y(32).
	let x = B64URL.encode(&public_point[1..33]);
	let y = B64URL.encode(&public_point[33..65]);
	format!(
		r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","alg":"ES256","x":"{x}","y":"{y}"}}]}}"#
	)
}

#[test]
fn parses_ec_key_into_uncompressed_point() {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let point = pair.public_key().as_ref();

	let jwks = ec_jwks(point, "ec-1");
	let keys = parse_jwks(&jwks, Algorithm::Es256).expect("parse");
	assert_eq!(keys.len(), 1);
	assert_eq!(keys[0].kid, "ec-1");
	assert_eq!(keys[0].algorithm, Algorithm::Es256);
	// The converted key is exactly the ring uncompressed point.
	assert_eq!(keys[0].key, point);
}

#[test]
fn parses_rsa_key_into_pkcs1_der() {
	// A small but well-formed RSA JWK (n with the high bit set to exercise the
	// leading-zero rule). e = 65537 (AQAB).
	let n_bytes = vec![0xff; 256];
	let n = B64URL.encode(&n_bytes);
	let jwks = format!(r#"{{"keys":[{{"kty":"RSA","kid":"rsa-1","n":"{n}","e":"AQAB"}}]}}"#);
	let keys = parse_jwks(&jwks, Algorithm::Rs256).expect("parse");
	assert_eq!(keys.len(), 1);
	assert_eq!(keys[0].algorithm, Algorithm::Rs256);
	// DER: SEQUENCE { INTEGER 0x00‖n (257 bytes), INTEGER 0x010001 }.
	let der = &keys[0].key;
	assert_eq!(der[0], 0x30, "SEQUENCE tag");
	// First INTEGER content is 0x00 (sign byte) + 256 bytes of 0xff.
	let int_start = der.iter().position(|&b| b == 0x02).unwrap();
	assert_eq!(der[int_start], 0x02, "INTEGER tag");
	assert_eq!(der[int_start + 1], 0x82, "long-form length, 2 bytes");
	assert_eq!(
		u16::from_be_bytes([der[int_start + 2], der[int_start + 3]]),
		257
	);
	assert_eq!(der[int_start + 4], 0x00, "leading sign byte");
}

#[test]
fn parses_both_rsa_and_ec_in_one_jwks() {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let point = pair.public_key().as_ref();
	let x = B64URL.encode(&point[1..33]);
	let y = B64URL.encode(&point[33..65]);
	let jwks = format!(
		r#"{{"keys":[
		{{"kty":"RSA","kid":"r","n":"{}","e":"AQAB"}},
		{{"kty":"EC","crv":"P-256","kid":"e","alg":"ES256","x":"{x}","y":"{y}"}}
		]}}"#,
		B64URL.encode([0x80u8; 256])
	);
	let keys = parse_jwks(&jwks, Algorithm::Rs256).expect("parse");
	assert_eq!(keys.len(), 2);
	assert!(
		keys.iter()
			.any(|k| k.kid == "r" && k.algorithm == Algorithm::Rs256)
	);
	assert!(
		keys.iter()
			.any(|k| k.kid == "e" && k.algorithm == Algorithm::Es256)
	);
}

#[test]
fn skips_enc_use_and_unsupported_kinds() {
	let jwks = r#"{"keys":[
		{"kty":"RSA","kid":"enc","use":"enc","n":"AAAA","e":"AQAB"},
		{"kty":"oct","kid":"sym","k":"AAAA"},
		{"kty":"EC","crv":"P-384","kid":"p384","x":"AAAA","y":"AAAA"}
	]}"#;
	// Nothing usable remains.
	assert_eq!(parse_jwks(jwks, Algorithm::Rs256), Err(OidcError::NoKeys));
}

#[test]
fn empty_jwks_is_no_keys() {
	assert_eq!(
		parse_jwks(r#"{"keys":[]}"#, Algorithm::Rs256),
		Err(OidcError::NoKeys)
	);
}

#[test]
fn malformed_json_is_bad_json() {
	assert!(matches!(
		parse_jwks("not json", Algorithm::Rs256),
		Err(OidcError::BadJson(_))
	));
}

#[test]
fn converted_ec_key_verifies_a_signed_token() {
	// End-to-end: a ring-signed ES256 token verifies against the key bytes
	// produced by parse_jwks (proving the JWK→point conversion is ring-usable).
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let jwks = ec_jwks(pair.public_key().as_ref(), "k");
	let keys = parse_jwks(&jwks, Algorithm::Es256).expect("parse");

	let header = B64URL.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
	let payload = B64URL.encode(br#"{"iss":"i","aud":"a","exp":2000}"#);
	let input = format!("{header}.{payload}");
	let sig = pair.sign(&rng, input.as_bytes()).unwrap();
	let token = format!("{input}.{}", B64URL.encode(sig.as_ref()));

	let validation = crate::jwt::Validation {
		now: 1000,
		issuer: Some("i"),
		audience: Some("a"),
	};
	assert!(crate::jwt::validate(&token, Algorithm::Es256, &keys[0].key, &validation).is_ok());
}

#[tokio::test]
async fn fetch_keys_rejects_non_https() {
	let client = reqwest::Client::new();
	assert_eq!(
		fetch_keys(
			&client,
			"http://idp.example/.well-known/openid-configuration",
			Algorithm::Rs256
		)
		.await,
		Err(OidcError::InsecureUrl)
	);
}
