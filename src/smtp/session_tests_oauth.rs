//! OAUTHBEARER/XOAUTH2 SMTP authentication tests.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

fn reply_code(action: &Action) -> u16 {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r) => r.code(),
		Action::Deliver(r, _) => r.code(),
		Action::CollectChunk { .. } => 0,
	}
}

fn auth_directory() -> Arc<Directory> {
	Arc::new(Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

/// An ES256 verifier plus its signing key.
fn verifier_and_key() -> (Arc<crate::oauth::OauthVerifier>, EcdsaKeyPair, SystemRandom) {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
	let pair =
		EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
	let public_b64 = B64.encode(pair.public_key().as_ref());
	let verifier = Arc::new(
		crate::oauth::OauthVerifier::new("https://idp.example", "mail", "ES256", &public_b64)
			.expect("verifier"),
	);
	(verifier, pair, rng)
}

fn bearer_response(pair: &EcdsaKeyPair, rng: &SystemRandom, email: &str) -> String {
	let header = B64URL.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
	let payload = B64URL.encode(
		serde_json::to_vec(&serde_json::json!({
			"iss": "https://idp.example",
			"aud": "mail",
			"email": email,
			"exp": 99_999_999_999u64,
		}))
		.unwrap(),
	);
	let input = format!("{header}.{payload}");
	let sig = pair.sign(rng, input.as_bytes()).unwrap();
	let token = format!("{input}.{}", B64URL.encode(sig.as_ref()));
	B64.encode(format!("n,a={email},\x01auth=Bearer {token}\x01\x01"))
}

#[test]
fn oauthbearer_authenticates_with_valid_token() {
	let (verifier, pair, rng) = verifier_and_key();
	let response = bearer_response(&pair, &rng, "alice@example.org");

	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_oauth(verifier);
	session.command_line("EHLO client.example.org");
	let action = session.command_line(&format!("AUTH OAUTHBEARER {response}"));
	assert_eq!(reply_code(&action), 235);
	assert_eq!(session.authenticated(), Some("alice"));
}

#[test]
fn ehlo_without_verifier_hides_oauth_mechanisms() {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	let Action::Continue(reply) = session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("OAUTHBEARER"), "{reply}");
}

#[test]
fn oauthbearer_rejects_garbage_token() {
	let (verifier, _pair, _rng) = verifier_and_key();
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active()
		.with_oauth(verifier);
	session.command_line("EHLO client.example.org");
	let response = B64.encode("n,a=alice@example.org,\x01auth=Bearer not.a.jwt\x01\x01");
	let action = session.command_line(&format!("AUTH OAUTHBEARER {response}"));
	assert_eq!(reply_code(&action), 535);
	assert_eq!(session.authenticated(), None);
}
