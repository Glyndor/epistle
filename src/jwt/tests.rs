//! Tests for JWT validation, signing ES256 tokens with ring.

use super::*;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

/// An ES256 key pair and its public point.
struct TestKey {
	pair: EcdsaKeyPair,
	public: Vec<u8>,
	rng: SystemRandom,
}

fn key() -> TestKey {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("gen");
	let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
		.expect("parse");
	let public = pair.public_key().as_ref().to_vec();
	TestKey { pair, public, rng }
}

/// Build a signed ES256 token from a claims JSON object.
fn sign(key: &TestKey, claims: &serde_json::Value) -> String {
	let header = serde_json::json!({"alg": "ES256", "typ": "JWT"});
	let header_b64 = B64URL.encode(serde_json::to_vec(&header).unwrap());
	let payload_b64 = B64URL.encode(serde_json::to_vec(claims).unwrap());
	let signing_input = format!("{header_b64}.{payload_b64}");
	let signature = key
		.pair
		.sign(&key.rng, signing_input.as_bytes())
		.expect("sign");
	format!("{signing_input}.{}", B64URL.encode(signature.as_ref()))
}

fn validation<'a>(now: u64) -> Validation<'a> {
	Validation {
		now,
		issuer: Some("https://issuer.example"),
		audience: Some("mail"),
	}
}

fn claims(exp: u64) -> serde_json::Value {
	serde_json::json!({
		"sub": "alice@example.org",
		"iss": "https://issuer.example",
		"aud": "mail",
		"exp": exp,
	})
}

#[test]
fn valid_token_passes_and_exposes_claims() {
	let k = key();
	let token = sign(&k, &claims(2000));
	let result = validate(&token, Algorithm::Es256, &k.public, &validation(1000)).expect("valid");
	assert_eq!(result.string("sub"), Some("alice@example.org"));
}

#[test]
fn tampered_payload_fails_signature() {
	let k = key();
	let mut token = sign(&k, &claims(2000));
	// Flip a character in the payload segment.
	let dot = token.find('.').unwrap();
	let byte = token.as_bytes()[dot + 1];
	let replacement = if byte == b'A' { 'B' } else { 'A' };
	token.replace_range(dot + 1..dot + 2, &replacement.to_string());
	assert_eq!(
		validate(&token, Algorithm::Es256, &k.public, &validation(1000)),
		Err(JwtError::BadSignature)
	);
}

#[test]
fn expired_token_is_rejected() {
	let k = key();
	let token = sign(&k, &claims(500));
	assert_eq!(
		validate(&token, Algorithm::Es256, &k.public, &validation(1000)),
		Err(JwtError::Expired)
	);
}

#[test]
fn wrong_issuer_and_audience_rejected() {
	let k = key();
	let token = sign(
		&k,
		&serde_json::json!({"iss": "https://evil.example", "aud": "mail", "exp": 2000}),
	);
	assert_eq!(
		validate(&token, Algorithm::Es256, &k.public, &validation(1000)),
		Err(JwtError::WrongIssuer)
	);

	let token = sign(
		&k,
		&serde_json::json!({"iss": "https://issuer.example", "aud": "other", "exp": 2000}),
	);
	assert_eq!(
		validate(&token, Algorithm::Es256, &k.public, &validation(1000)),
		Err(JwtError::WrongAudience)
	);
}

#[test]
fn audience_array_matches() {
	let k = key();
	let token = sign(
		&k,
		&serde_json::json!({"iss": "https://issuer.example", "aud": ["other", "mail"], "exp": 2000}),
	);
	assert!(validate(&token, Algorithm::Es256, &k.public, &validation(1000)).is_ok());
}

#[test]
fn algorithm_mismatch_rejected() {
	let k = key();
	let token = sign(&k, &claims(2000));
	// The token is ES256; demanding RS256 must fail before signature checks.
	assert_eq!(
		validate(&token, Algorithm::Rs256, &k.public, &validation(1000)),
		Err(JwtError::AlgorithmMismatch)
	);
}

#[test]
fn malformed_token_rejected() {
	let k = key();
	assert_eq!(
		validate("not-a-jwt", Algorithm::Es256, &k.public, &validation(1000)),
		Err(JwtError::Malformed)
	);
}
