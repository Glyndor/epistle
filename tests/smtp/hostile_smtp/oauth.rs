//! OAUTHBEARER and XOAUTH2 on the real listener, over TLS, with tokens an
//! unauthenticated attacker can forge or replay.
//!
//! Every refused token must answer the same `535`, leave the session
//! unauthenticated (a relay to a foreign domain stays denied) and deliver
//! nothing. The accepted control proves the fixture works before the attacks.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use epistle::oauth::OauthVerifier;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};

use super::harness::*;
use super::tls::Tls;

const ISSUER: &str = "https://idp.example";
const AUDIENCE: &str = "mail";
const REFUSED: &str = "535 5.7.8 authentication credentials invalid\r\n";
const ACCOUNT: &str = "tester@epistle.test";

struct Idp {
	pair: EcdsaKeyPair,
	rng: SystemRandom,
	verifier: Arc<OauthVerifier>,
}

impl Idp {
	fn new() -> Self {
		let rng = SystemRandom::new();
		let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
		let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
			.unwrap();
		let verifier = Arc::new(
			OauthVerifier::new(
				ISSUER,
				AUDIENCE,
				"ES256",
				&B64.encode(pair.public_key().as_ref()),
			)
			.expect("verifier"),
		);
		Self {
			pair,
			rng,
			verifier,
		}
	}

	fn claims() -> Value {
		json!({
			"iss": ISSUER,
			"aud": AUDIENCE,
			"email": ACCOUNT,
			"email_verified": true,
			"exp": 99_999_999_999u64,
		})
	}

	/// A token signed by the provider over exactly these header and claims.
	fn token(&self, header: &Value, claims: &Value) -> String {
		let input = format!(
			"{}.{}",
			B64URL.encode(serde_json::to_vec(header).unwrap()),
			B64URL.encode(serde_json::to_vec(claims).unwrap())
		);
		let signature = self.pair.sign(&self.rng, input.as_bytes()).unwrap();
		format!("{input}.{}", B64URL.encode(signature.as_ref()))
	}

	fn valid(&self) -> String {
		self.token(&json!({"alg": "ES256", "typ": "JWT"}), &Self::claims())
	}

	fn claims_with(&self, key: &str, value: Option<Value>) -> String {
		let mut claims = Self::claims();
		match value {
			Some(value) => claims[key] = value,
			None => {
				claims.as_object_mut().unwrap().remove(key);
			}
		}
		self.token(&json!({"alg": "ES256", "typ": "JWT"}), &claims)
	}
}

/// The initial response RFC 7628 frames around a bearer token.
fn response(token: &str) -> String {
	B64.encode(format!("n,a={ACCOUNT},\x01auth=Bearer {token}\x01\x01"))
}

fn directory_server(
	idp: &Idp,
) -> impl FnOnce(epistle::smtp::server::Server) -> epistle::smtp::server::Server + use<> {
	let verifier = idp.verifier.clone();
	move |server| server.with_oauth(verifier)
}

async fn attempt<S: AsyncRead + AsyncWrite + Unpin>(client: &mut S, mechanism: &str, token: &str) {
	send(
		client,
		format!("AUTH {mechanism} {}\r\n", response(token)).as_bytes(),
	)
	.await;
}

/// Not signed in: a relay to a domain the server does not host is denied and
/// nothing was delivered.
async fn still_anonymous<S: AsyncRead + AsyncWrite + Unpin>(client: &mut S, server: &Harness) {
	send(client, b"MAIL FROM:<sender@remote.test>\r\n").await;
	expect(client, OK).await;
	send(client, b"RCPT TO:<someone@foreign.test>\r\n").await;
	expect(client, "550 5.7.1 relaying denied\r\n").await;
	assert!(server.sink.messages().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_valid_token_signs_in_over_both_mechanisms() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let idp = Idp::new();
	let server = Harness::start(|s| directory_server(&idp)(tls.server(s))).await;
	for mechanism in ["OAUTHBEARER", "XOAUTH2"] {
		let mut client = tls.connect(&server).await;
		attempt(&mut client, mechanism, &idp.valid()).await;
		expect(&mut client, "235 2.7.0 authentication successful\r\n").await;
		quit(&mut client).await;
	}
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_and_replayed_tokens_never_sign_in() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let idp = Idp::new();
	let other = Idp::new();
	let server = Harness::start(|s| directory_server(&idp)(tls.server(s))).await;

	let valid = idp.valid();
	let mut parts = valid.split('.');
	let (header, payload) = (parts.next().unwrap(), parts.next().unwrap());
	let unsigned = |alg: &str| {
		format!(
			"{}.{payload}.",
			B64URL.encode(serde_json::to_vec(&json!({"alg": alg, "typ": "JWT"})).unwrap())
		)
	};
	let swapped_payload = {
		let mut claims = Idp::claims();
		claims["email"] = json!("admin@epistle.test");
		format!(
			"{header}.{}.{}",
			B64URL.encode(serde_json::to_vec(&claims).unwrap()),
			valid.rsplit('.').next().unwrap()
		)
	};
	let cases: Vec<(&str, String)> = vec![
		("alg none, empty signature", unsigned("none")),
		("alg HS256 with the ES256 signature", unsigned("HS256")),
		("payload swapped, signature kept", swapped_payload),
		(
			"valid signature, header names RS256",
			idp.token(&json!({"alg": "RS256", "typ": "JWT"}), &Idp::claims()),
		),
		(
			"valid signature, header names none",
			idp.token(&json!({"alg": "none"}), &Idp::claims()),
		),
		(
			"valid signature, header without alg",
			idp.token(&json!({"typ": "JWT"}), &Idp::claims()),
		),
		(
			"signed by another key",
			other.token(&json!({"alg": "ES256"}), &Idp::claims()),
		),
		(
			"another audience",
			idp.claims_with("aud", Some(json!("other"))),
		),
		(
			"another issuer",
			idp.claims_with("iss", Some(json!("https://evil.example"))),
		),
		("expired", idp.claims_with("exp", Some(json!(1)))),
		("no expiry", idp.claims_with("exp", None)),
		(
			"expiry as text",
			idp.claims_with("exp", Some(json!("99999999999"))),
		),
		(
			"email not verified",
			idp.claims_with("email_verified", Some(json!(false))),
		),
		(
			"email_verified missing",
			idp.claims_with("email_verified", None),
		),
		("no email", idp.claims_with("email", None)),
		(
			"an address no account owns",
			idp.claims_with("email", Some(json!("nobody@epistle.test"))),
		),
		(
			"an address in a foreign domain",
			idp.claims_with("email", Some(json!("tester@foreign.test"))),
		),
		("not a token", "not.a.jwt".to_string()),
		("empty parts", "..".to_string()),
		("one part", "AAAA".to_string()),
	];
	for (name, token) in &cases {
		let mut client = tls.connect(&server).await;
		attempt(&mut client, "OAUTHBEARER", token).await;
		expect(&mut client, REFUSED).await;
		still_anonymous(&mut client, &server).await;
		quit(&mut client).await;
		eprintln!("refused: {name}");
	}
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_initial_responses_are_refused_without_a_panic() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let idp = Idp::new();
	let server = Harness::start(|s| directory_server(&idp)(tls.server(s))).await;
	let token = idp.valid();
	let responses = [
		"!!!not-base64!!!".to_string(),
		B64.encode([0xff, 0xfe, 0xfd]),
		B64.encode("n,,\x01auth=Bearer \x01\x01"),
		B64.encode("n,,\x01auth=Basic dGVzdGVyOnRlc3Rlcg==\x01\x01"),
		B64.encode(format!("n,,\x01auth=bearer {token}\x01\x01")),
		B64.encode("\x01\x01\x01"),
	];
	for encoded in &responses {
		let mut client = tls.connect(&server).await;
		send(
			&mut client,
			format!("AUTH OAUTHBEARER {encoded}\r\n").as_bytes(),
		)
		.await;
		let reply = line(&mut client).await.expect("reply").expect("open");
		assert!(
			reply.starts_with("535 ") || reply.starts_with("501 "),
			"signed in or unexpected reply to {encoded:.40}: {reply:?}"
		);
		still_anonymous(&mut client, &server).await;
		quit(&mut client).await;
	}
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_the_size_of_a_message_is_cut_off_before_it_is_parsed() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let idp = Idp::new();
	let server = Harness::start(|s| directory_server(&idp)(tls.server(s))).await;
	let mut client = tls.connect(&server).await;
	let giant = format!(
		"{}.{}.{}",
		"A".repeat(40_000),
		"B".repeat(40_000),
		"C".repeat(40_000)
	);
	// The server cuts the line off while the client is still writing, so
	// the write may fail and the `500` may be lost to the reset: both
	// are the connection being closed. A `235` is the only wrong answer.
	let command = format!("AUTH OAUTHBEARER {}\r\n", response(&giant));
	let _ = tokio::time::timeout(
		crate::common::BANNER_READ_DEADLINE,
		tokio::io::AsyncWriteExt::write_all(&mut client, command.as_bytes()),
	)
	.await;
	if let Ok(Some(reply)) = line(&mut client).await {
		assert!(reply.starts_with("500 5.5.2 line too long"), "{reply:?}");
		closed(&mut client).await;
	}
	assert!(server.sink.messages().is_empty());
	server.healthy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_third_refused_token_closes_the_connection() {
	if !super::enabled() {
		return;
	}
	let tls = Tls::new();
	let idp = Idp::new();
	let server = Harness::start(|s| directory_server(&idp)(tls.server(s))).await;
	let mut client = tls.connect(&server).await;
	let bad = idp.claims_with("aud", Some(json!("other")));
	for _ in 0..3 {
		attempt(&mut client, "XOAUTH2", &bad).await;
		expect(&mut client, REFUSED).await;
	}
	closed(&mut client).await;
	// A valid token on a fresh connection still works: the refusal is
	// per session and does not lock the account out for the owner.
	let mut next = tls.connect(&server).await;
	attempt(&mut next, "OAUTHBEARER", &idp.valid()).await;
	expect(&mut next, "235 2.7.0 authentication successful\r\n").await;
	quit(&mut next).await;
	server.healthy().await;
}
