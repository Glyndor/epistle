//! `serve` hands the identity declarations of `[oauth]` to the verifier: the
//! unit tests of the verifier cannot see a declaration the wiring dropped.

use crate::cli::serve::tasks::build_oauth_verifier;
use crate::config::Config;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

fn key_pair() -> (EcdsaKeyPair, SystemRandom) {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("key");
	let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
		.expect("pair");
	(pair, rng)
}

fn token(pair: &EcdsaKeyPair, rng: &SystemRandom, claims: serde_json::Value) -> String {
	let header = B64URL.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
	let payload = B64URL.encode(serde_json::to_vec(&claims).expect("claims"));
	let input = format!("{header}.{payload}");
	let sig = pair.sign(rng, input.as_bytes()).expect("sign");
	format!("{input}.{}", B64URL.encode(sig.as_ref()))
}

fn config(pair: &EcdsaKeyPair, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp/unused\"\n[oauth]\n\
		 issuer = \"https://idp.example\"\naudience = \"mail\"\nalgorithm = \"ES256\"\n\
		 public_key = \"{}\"\n{extra}",
		B64.encode(pair.public_key().as_ref())
	))
	.expect("config")
}

fn claims(extra: serde_json::Value) -> serde_json::Value {
	let mut base = serde_json::json!({
		"iss": "https://idp.example",
		"aud": "mail",
		"exp": 99_999_999_999u64,
		"email": "alice@example.org",
	});
	base.as_object_mut()
		.expect("object")
		.extend(extra.as_object().expect("object").clone());
	base
}

#[tokio::test]
async fn the_declarations_of_the_section_reach_the_verifier() {
	let (pair, rng) = key_pair();
	let unstated = token(&pair, &rng, claims(serde_json::json!({})));

	let strict = build_oauth_verifier(&config(&pair, ""))
		.await
		.expect("build")
		.expect("verifier");
	assert_eq!(strict.verify(&unstated, 1), None);
	assert!(!strict.second_factor_attested());

	let declared = config(
		&pair,
		"allow_unverified_email = true\nidp_enforces_second_factor = true\n",
	);
	let declared = build_oauth_verifier(&declared)
		.await
		.expect("build")
		.expect("verifier");
	assert_eq!(
		declared.verify(&unstated, 1).as_deref(),
		Some("alice@example.org")
	);
	assert!(declared.second_factor_attested());
}

#[tokio::test]
async fn a_signing_key_makes_the_tokens_the_built_in_servers() {
	let (pair, rng) = key_pair();
	let own = build_oauth_verifier(&config(&pair, "signing_key = \"S\"\n"))
		.await
		.expect("build")
		.expect("verifier");
	assert!(own.second_factor_attested());
	let named = token(
		&pair,
		&rng,
		claims(serde_json::json!({"sub": "alice", "email": null})),
	);
	assert_eq!(own.verify(&named, 1).as_deref(), Some("alice"));
}
