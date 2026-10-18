//! Shared fixture for the tests that prove every authentication path applies
//! the same account rules: one directory with an account for each reason a
//! login may be refused, and the helpers the SMTP and IMAP sessions need to
//! present each kind of proof.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use super::Directory;
use crate::directory_store::AppPassword;
use crate::smtp::scram::{ScramCredentials, ScramStored};
use crate::test_fixtures as fixtures;

/// The domain switched off in [`gate_directory`].
pub(crate) const OFF_DOMAIN: &str = "off.example";

/// The accounts of [`gate_directory`] and why each one is (or is not) allowed
/// to sign in. Every account has the same password and a SCRAM verifier, so a
/// refusal can only come from the account rules.
pub(crate) const OPEN: &str = "alice";
/// Administratively disabled.
pub(crate) const DISABLED: &str = "bob";
/// Has a TOTP secret, so a password alone is not enough.
pub(crate) const TWO_FACTOR: &str = "carol";
/// Its only address lives in a switched-off domain.
pub(crate) const OFF_DOMAIN_ACCOUNT: &str = "frank";

/// The TOTP secret of [`TWO_FACTOR`], raw bytes, fixed for the process.
pub(crate) fn totp_secret() -> [u8; 16] {
	static VALUE: std::sync::LazyLock<[u8; 16]> = std::sync::LazyLock::new(fixtures::bytes);
	*VALUE
}

/// A directory with one account per refusal reason, plus an open account.
pub(crate) fn gate_directory() -> Directory {
	let stored = ScramStored::from_credentials(&ScramCredentials::derive(
		fixtures::password(),
		fixtures::salt(),
		4096,
	));
	let names = [OPEN, DISABLED, TWO_FACTOR, OFF_DOMAIN_ACCOUNT];
	let hash = crate::smtp::auth::tests::hash(fixtures::password());
	Directory::new(
		["example.org".to_string(), OFF_DOMAIN.to_string()],
		[
			("alice@example.org".to_string(), OPEN.to_string()),
			("bob@example.org".to_string(), DISABLED.to_string()),
			("carol@example.org".to_string(), TWO_FACTOR.to_string()),
			(
				format!("frank@{OFF_DOMAIN}"),
				OFF_DOMAIN_ACCOUNT.to_string(),
			),
		],
	)
	.with_password_hashes(names.map(|name| (name.to_string(), hash.clone())))
	.with_scram(names.map(|name| (name.to_string(), stored.clone())))
	.with_totp([(
		TWO_FACTOR.to_string(),
		crate::totp::encode_base32(&totp_secret()),
	)])
	.with_disabled([DISABLED.to_string()])
	.with_disabled_domains([OFF_DOMAIN.to_string()])
}

/// [`gate_directory`] plus app passwords on `alice`: one expired and one
/// limited to a network the test peer is not on.
pub(crate) fn gate_directory_with_app_passwords() -> (Directory, &'static str, &'static str) {
	let secret_expired = fixtures::second_password();
	let secret_cidr = fixtures::wrong_password();
	let entry = |label: &str, secret: &str, expires_at, ip_cidr: Option<&str>| AppPassword {
		label: label.to_string(),
		hash: crate::smtp::auth::tests::hash(secret),
		expires_at,
		ip_cidr: ip_cidr.map(str::to_string),
		save_sent: None,
	};
	let directory = gate_directory().with_app_passwords([
		(
			OPEN.to_string(),
			entry("expired", secret_expired, Some(1), None),
		),
		(
			OPEN.to_string(),
			entry("elsewhere", secret_cidr, None, Some("198.51.100.0/24")),
		),
	]);
	(directory, secret_expired, secret_cidr)
}

/// A shared handle for a session.
pub(crate) fn gate_directory_arc() -> Arc<Directory> {
	Arc::new(gate_directory())
}

/// A verifier that trusts one throwaway ES256 key, and the key itself.
pub(crate) fn verifier_and_key() -> (Arc<crate::oauth::OauthVerifier>, EcdsaKeyPair, SystemRandom) {
	let rng = SystemRandom::new();
	let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
		.expect("generate signing key");
	let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
		.expect("load signing key");
	let public_b64 = B64.encode(pair.public_key().as_ref());
	let verifier = Arc::new(
		crate::oauth::OauthVerifier::new("https://idp.example", "mail", "ES256", &public_b64)
			.expect("verifier"),
	);
	(verifier, pair, rng)
}

/// The base64 SASL initial response of an OAUTHBEARER exchange carrying a
/// token the verifier trusts, issued for `email`.
pub(crate) fn bearer_response(pair: &EcdsaKeyPair, rng: &SystemRandom, email: &str) -> String {
	let header = B64URL.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
	let payload = B64URL.encode(
		serde_json::to_vec(&serde_json::json!({
			"iss": "https://idp.example",
			"aud": "mail",
			"email": email,
			"exp": 99_999_999_999u64,
		}))
		.expect("claims"),
	);
	let input = format!("{header}.{payload}");
	let sig = pair.sign(rng, input.as_bytes()).expect("sign token");
	let token = format!("{input}.{}", B64URL.encode(sig.as_ref()));
	B64.encode(format!("n,a={email},\x01auth=Bearer {token}\x01\x01"))
}

/// A SCRAM-SHA-256 client-final message proving knowledge of `password`
/// against `server_first`, derived at the 4096 iterations the fixture
/// verifiers use. `client_first_bare` is the part of the client-first after
/// the GS2 header, such as `n=alice,r=CN`.
pub(crate) fn scram_client_final(
	client_first_bare: &str,
	server_first: &str,
	password: &str,
) -> String {
	use ring::{digest, hmac, pbkdf2};
	let field = |key: &str| {
		server_first
			.split(',')
			.find_map(|part| part.strip_prefix(key))
			.expect("field in server-first")
	};
	let salt = B64.decode(field("s=")).expect("base64 salt");
	let without_proof = format!("c=biws,r={}", field("r="));
	let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		std::num::NonZeroU32::new(4096).expect("non-zero"),
		&salt,
		password.as_bytes(),
		&mut salted,
	);
	let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
	let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
	let signature = hmac::sign(
		&hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()),
		auth_message.as_bytes(),
	);
	let proof: Vec<u8> = client_key
		.as_ref()
		.iter()
		.zip(signature.as_ref())
		.map(|(a, b)| a ^ b)
		.collect();
	format!("{without_proof},p={}", B64.encode(proof))
}

/// The current TOTP code of [`TWO_FACTOR`], six digits.
pub(crate) fn current_totp_code() -> String {
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_secs())
		.unwrap_or(0);
	format!("{:06}", crate::totp::totp(&totp_secret(), now))
}

/// A directory whose only account, `alice`, carries a SCRAM verifier as a
/// current install stores it: 600000 iterations and a random-looking salt. The
/// keys are arbitrary, which is enough to look at the challenge but never to
/// finish an exchange.
pub(crate) fn directory_with_production_verifier() -> Directory {
	use crate::smtp::scram::SCRAM_ITERATIONS;
	let stored = ScramStored::from_credentials(&ScramCredentials {
		salt: fixtures::salt().to_vec(),
		iterations: SCRAM_ITERATIONS,
		stored_key: [7u8; 32],
		server_key: [9u8; 32],
	});
	Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), OPEN.to_string())],
	)
	.with_password_hashes([(
		OPEN.to_string(),
		crate::smtp::auth::tests::hash(fixtures::password()),
	)])
	.with_scram([(OPEN.to_string(), stored)])
}

/// The `s=` salt and `i=` count of a server-first message.
pub(crate) fn salt_and_iterations(server_first: &str) -> (Vec<u8>, u32) {
	let field = |key: &str| {
		server_first
			.split(',')
			.find_map(|part| part.strip_prefix(key))
			.expect("field in server-first")
	};
	(
		B64.decode(field("s=")).expect("base64 salt"),
		field("i=").parse().expect("iteration count"),
	)
}
