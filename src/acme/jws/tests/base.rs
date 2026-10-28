use super::*;
use crate::test_fixtures as fixtures;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

#[test]
fn generate_and_restore_roundtrip() {
	let (key, pkcs8) = AccountKey::generate().expect("generate");
	let restored = AccountKey::from_pkcs8(&pkcs8).expect("restore");
	// Same key → same public JWK.
	assert_eq!(key.jwk(), restored.jwk());
}

#[test]
fn jwk_is_p256_ec() {
	let (key, _) = AccountKey::generate().expect("generate");
	let jwk = key.jwk();
	assert_eq!(jwk["kty"], "EC");
	assert_eq!(jwk["crv"], "P-256");
	assert!(jwk["x"].as_str().is_some_and(|x| !x.is_empty()));
	assert!(jwk["y"].as_str().is_some_and(|y| !y.is_empty()));
}

#[test]
fn sign_produces_verifiable_flattened_jws() {
	let (key, _) = AccountKey::generate().expect("generate");
	let jws_str = key
		.sign(
			"https://acme.example/order",
			fixtures::nonce(),
			br#"{"x":1}"#,
			None,
		)
		.expect("sign");
	let jws: Value = serde_json::from_str(&jws_str).expect("json");

	let protected = jws["protected"].as_str().expect("protected");
	let payload = jws["payload"].as_str().expect("payload");
	let signature = B64
		.decode(jws["signature"].as_str().expect("sig"))
		.expect("b64 sig");

	// The signature verifies over `protected.payload`.
	let signing_input = format!("{protected}.{payload}");
	let public = key.key_pair.public_key().as_ref().to_vec();
	UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
		.verify(signing_input.as_bytes(), &signature)
		.expect("signature verifies");

	// newAccount form embeds the jwk, not a kid.
	let header: Value =
		serde_json::from_slice(&B64.decode(protected).expect("b64 header")).expect("header");
	assert_eq!(header["alg"], "ES256");
	assert_eq!(header["url"], "https://acme.example/order");
	assert!(header["jwk"].is_object());
	assert!(header["kid"].is_null());
}

#[test]
fn thumbprint_is_stable_and_key_authorization_formats() {
	let (key, pkcs8) = AccountKey::generate().expect("generate");
	let restored = AccountKey::from_pkcs8(&pkcs8).expect("restore");
	// Deterministic for the same key.
	assert_eq!(key.thumbprint(), restored.thumbprint());
	// base64url has no padding.
	assert!(!key.thumbprint().contains('='));
	// Key authorization is token "." thumbprint.
	let auth = key.key_authorization("tok123");
	assert_eq!(auth, format!("tok123.{}", key.thumbprint()));

	// DNS-01 value is base64url(sha256(key authorization)): 43 chars, no pad.
	let dns = key.dns01_value("tok123");
	assert_eq!(dns.len(), 43, "{dns}");
	assert!(!dns.contains('='), "{dns}");
	assert_eq!(dns, restored.dns01_value("tok123"));
}

#[test]
fn kid_form_omits_jwk() {
	let (key, _) = AccountKey::generate().expect("generate");
	let jws_str = key
		.sign(
			"https://acme.example/order",
			fixtures::nonce(),
			b"{}",
			Some("https://acme.example/acct/1"),
		)
		.expect("sign");
	let jws: Value = serde_json::from_str(&jws_str).expect("json");
	let header: Value =
		serde_json::from_slice(&B64.decode(jws["protected"].as_str().unwrap()).unwrap()).unwrap();
	assert_eq!(header["kid"], "https://acme.example/acct/1");
	assert!(header["jwk"].is_null());
}
