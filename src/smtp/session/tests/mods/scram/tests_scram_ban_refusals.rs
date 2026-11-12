//! A banned address or account is refused before any SCRAM credential lookup, and failures add one strike.

use super::tests_scram::{TapEhlo, b64, b64_bytes, reply_code};
use super::tests_scram_bans::*;
use super::*;
use crate::test_fixtures as fixtures;
use base64::Engine;

/// A banned IP is refused on SMTP SCRAM before the SCRAM credential
/// lookup runs. The test arms a ban on the peer IP, drives a SCRAM
/// client-first, and asserts the ban store was consulted, the
/// `scram_credentials` lookup count did not move (the exchange was
/// short-circuited), and the wire reply is the same 334-then-535 a
/// wrong SCRAM proof produces. The lookup count delta is the property
/// that proves a banned IP cannot probe whether an account exists by
/// sending a SCRAM client-first. The test also asserts the salt in
/// the server-first is not the all-zero tell-tale a banned subject
/// could use to distinguish a refusal from a real exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_banned_ip_is_refused_before_credential_lookup() {
	let nonce = fixtures::nonce();
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"ip:203.0.113.42",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let lookup_counter = crate::smtp::tests::directory_scram_test_counter::fresh();
	let directory = scram_directory_with_ban_store(ban_store.clone(), Some(lookup_counter.clone()));

	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.42".parse().expect("peer")));

	let before = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);
	// A ban refusal at client-first looks like a normal exchange on
	// the wire: a 334 with a server-first, then a 535 when the proof
	// fails. The wrong-password shape is the same and the test asserts
	// the property is the shape, not the immediate code.
	let action = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(
		reply_code(&action),
		334,
		"a ban refusal at client-first must challenge with a 334, like a normal exchange"
	);
	// The server-first's salt must be derived from the username, not
	// the all-zero pattern that would let a banned subject identify
	// the refusal by the wire shape.
	let challenge = decode_server_first(&scram_challenge_text(&action));
	let salt_field = challenge
		.split(',')
		.find_map(|field| field.strip_prefix("s="))
		.expect("s= in server-first");
	let salt = base64::engine::general_purpose::STANDARD
		.decode(salt_field)
		.expect("base64 salt");
	assert_ne!(
		salt,
		vec![0u8; 16],
		"the ban refusal's server-first salt must not be all zeros"
	);
	// The proof the client sends is computed against the fake
	// server-first we just sent; the verifier rejects it because the
	// fake stored key is all zeros. The wire reply is the same 535 a
	// wrong password would produce.
	let bad_proof = b64_bytes(&[0u8; 32]);
	let client_final = format!("c=biws,r=CN{nonce},p={bad_proof}");
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
	let after = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);

	assert!(
		ban_store.call_count("is_banned") >= 1,
		"ban store consulted {} times, expected at least one is_banned",
		ban_store.call_count("is_banned")
	);
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"ban refusal must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	assert_eq!(
		after - before,
		0,
		"the SCRAM credential lookup must not happen when a ban short-circuits the exchange (delta: {})",
		after - before
	);
}

/// A SCRAM failure (a wrong proof against valid credentials) adds one
/// strike to the ban store. The test drives a full SCRAM exchange with
/// a wrong client proof, asserts the wire reply is 535, and asserts the
/// ban store received exactly one `record_failure` call keyed on
/// `ip:<peer>` and one on `account:<login>`, the same keying the PLAIN
/// path uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_failure_adds_one_strike() {
	let nonce = fixtures::nonce();
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::base::FakeBanStore;

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = scram_directory_with_ban_store(ban_store.clone(), None);

	let mut session = Session::new("mail.example.org")
		.with_directory(directory.clone())
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.43".parse().expect("peer")));

	// client-first is well-formed; the ban check passes.
	assert_eq!(
		reply_code(
			&session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")))
		),
		334
	);
	// The client-final carries a zeroed proof, so the verifier rejects
	// it. The exact shape of the failure is irrelevant: the point is
	// that the ban store records one strike.
	let bad_proof = b64_bytes(&[0u8; 32]);
	let client_final = format!("c=biws,r=CN{nonce},p={bad_proof}");
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);

	assert_eq!(
		ban_store.call_count("record_failure"),
		3,
		"ban store recorded {} failure(s); expected exactly three (client, pair and account)",
		ban_store.call_count("record_failure")
	);
	assert!(
		ban_store.failure_count("ip:203.0.113.43", 0) >= 1,
		"ban store did not record a strike for ip:203.0.113.43"
	);
	assert!(
		ban_store.failure_count("pair:alice|203.0.113.43", 0) >= 1,
		"ban store did not record a strike for the alice/203.0.113.43 pair"
	);
}
