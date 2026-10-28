use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

fn signed_token(pair: &EcdsaKeyPair, rng: &SystemRandom, claims: &serde_json::Value) -> String {
	let header = B64URL.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
	let payload = B64URL.encode(serde_json::to_vec(claims).unwrap());
	let input = format!("{header}.{payload}");
	let sig = pair.sign(rng, input.as_bytes()).unwrap();
	format!("{input}.{}", B64URL.encode(sig.as_ref()))
}

#[test]
fn verifies_token_and_returns_email() {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let public_b64 = B64.encode(pair.public_key().as_ref());

	let verifier =
		OauthVerifier::new("https://idp.example", "mail", "ES256", &public_b64).expect("build");
	let token = signed_token(
		&pair,
		&rng,
		&serde_json::json!({
			"iss": "https://idp.example",
			"aud": "mail",
			"email": "alice@example.org",
			"email_verified": true,
			"exp": 2000,
		}),
	);
	assert_eq!(
		verifier.verify(&token, 1000).as_deref(),
		Some("alice@example.org")
	);
	// Expired or wrong-issuer tokens do not verify.
	assert_eq!(verifier.verify(&token, 3000), None);
}

#[test]
fn rejects_bad_configuration() {
	assert!(matches!(
		OauthVerifier::new("i", "a", "HS256", "AAAA"),
		Err(BuildError::UnsupportedAlgorithm)
	));
	assert!(matches!(
		OauthVerifier::new("i", "a", "ES256", "not base64!!!"),
		Err(BuildError::BadKey)
	));
}

#[test]
fn builds_rs256_verifier() {
	// The RS256 algorithm arm is accepted; the key bytes are decoded lazily.
	let verifier = OauthVerifier::new("i", "a", "rs256", "AAAA").expect("build");
	assert!(format!("{verifier:?}").contains("OauthVerifier"));
}

#[test]
fn a_token_with_only_a_subject_names_no_identity() {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let public_b64 = B64.encode(pair.public_key().as_ref());
	let verifier =
		OauthVerifier::new("https://idp.example", "mail", "ES256", &public_b64).expect("build");
	let token = signed_token(
		&pair,
		&rng,
		&serde_json::json!({
			"iss": "https://idp.example",
			"aud": "mail",
			"sub": "user-123",
			"exp": 2000,
		}),
	);
	assert_eq!(verifier.verify(&token, 1000), None);
}

/// Sign an ES256 token whose header carries `kid`, like an IdP-issued token.
fn signed_token_kid(
	pair: &EcdsaKeyPair,
	rng: &SystemRandom,
	kid: &str,
	claims: &serde_json::Value,
) -> String {
	let header = B64URL.encode(format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#));
	let payload = B64URL.encode(serde_json::to_vec(claims).unwrap());
	let input = format!("{header}.{payload}");
	let sig = pair.sign(rng, input.as_bytes()).unwrap();
	format!("{input}.{}", B64URL.encode(sig.as_ref()))
}

fn ec_keypair() -> (EcdsaKeyPair, SystemRandom, Vec<u8>) {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let point = pair.public_key().as_ref().to_vec();
	(pair, rng, point)
}

#[test]
fn jwks_verifier_selects_key_by_kid_and_verifies() {
	let (pair, rng, point) = ec_keypair();
	// Two cached keys; the token's kid selects the right one.
	let keys = vec![
		Jwk {
			kid: "other".to_string(),
			algorithm: Algorithm::Es256,
			key: vec![0x04; 65],
		},
		Jwk {
			kid: "live".to_string(),
			algorithm: Algorithm::Es256,
			key: point,
		},
	];
	let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
	let token = signed_token_kid(
		&pair,
		&rng,
		"live",
		&serde_json::json!({
			"iss": "https://idp.example",
			"aud": "mail",
			"email": "bob@example.org",
			"email_verified": true,
			"exp": 2000,
		}),
	);
	assert_eq!(
		verifier.verify(&token, 1000).as_deref(),
		Some("bob@example.org")
	);
}

#[test]
fn jwks_verifier_rejects_unknown_kid() {
	let (pair, rng, point) = ec_keypair();
	let keys = vec![Jwk {
		kid: "known".to_string(),
		algorithm: Algorithm::Es256,
		key: point,
	}];
	let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
	let token = signed_token_kid(
		&pair,
		&rng,
		"unknown",
		&serde_json::json!({"iss": "https://idp.example", "aud": "mail", "exp": 2000}),
	);
	assert_eq!(verifier.verify(&token, 1000), None);
}

#[test]
fn jwks_verifier_rejects_wrong_issuer_and_audience() {
	let (pair, rng, point) = ec_keypair();
	let keys = vec![Jwk {
		kid: "k".to_string(),
		algorithm: Algorithm::Es256,
		key: point,
	}];
	let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
	let bad_issuer = signed_token_kid(
		&pair,
		&rng,
		"k",
		&serde_json::json!({"iss": "https://evil.example", "aud": "mail", "exp": 2000}),
	);
	assert_eq!(verifier.verify(&bad_issuer, 1000), None);
	let bad_audience = signed_token_kid(
		&pair,
		&rng,
		"k",
		&serde_json::json!({"iss": "https://idp.example", "aud": "other", "exp": 2000}),
	);
	assert_eq!(verifier.verify(&bad_audience, 1000), None);
}

#[test]
fn jwks_verifier_uses_the_single_key_without_kid() {
	let (pair, rng, point) = ec_keypair();
	let keys = vec![Jwk {
		kid: String::new(),
		algorithm: Algorithm::Es256,
		key: point,
	}];
	let verifier = OauthVerifier::from_jwks("https://idp.example", "mail", keys);
	// No-kid header: the single cached key is used.
	let token = signed_token(
		&pair,
		&rng,
		&serde_json::json!({
			"iss": "https://idp.example",
			"aud": "mail",
			"email": "carol@example.org",
			"email_verified": true,
			"exp": 2000,
		}),
	);
	assert_eq!(
		verifier.verify(&token, 1000).as_deref(),
		Some("carol@example.org")
	);
}

#[test]
fn jwks_cache_is_exposed_for_static_and_oidc() {
	let oidc = OauthVerifier::from_jwks("i", "a", vec![]);
	assert!(oidc.jwks_cache().is_some());
	let static_v = OauthVerifier::new("i", "a", "ES256", "AAAA").expect("build");
	assert!(static_v.jwks_cache().is_none());
}
