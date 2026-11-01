//! The last round of the SMTP SCRAM exchange.
//!
//! SMTP has no room for the SASL "additional data with a successful
//! outcome" (RFC 4954 §4): the `235` cannot carry the server-final, so
//! the server sends it as a `334` challenge, the client checks its own
//! signature against it and answers with the empty line, and only then
//! is the session authenticated. These tests drive the whole dialogue
//! with a client that computes the SCRAM proof and the server
//! signature the way RFC 5802 §3 says, so the challenge the server
//! sends is checked against the one the client expects (the check
//! PEAR's `Auth_SASL_SCRAM::processOutcome` makes).

use super::tests_scram::{b64, b64_bytes, reply_code, scram_session};
use super::tests_scram_bans::{decode_server_first, scram_challenge_text};
use super::*;
use crate::test_fixtures as fixtures;

/// What the client sends in the last round, and what it expects back.
pub(in crate::smtp::session::tests::mods) struct Client {
	/// The client-final, proof included.
	final_message: String,
	/// The server-final the client expects (`v=<base64>`).
	server_final: String,
}

/// The client side of a SCRAM-SHA-256 exchange against the server-first
/// the server answered: the client-final with its proof, and the
/// server-final the client will verify the challenge against.
fn client_exchange(server_first: &str, password: &str) -> Client {
	use base64::Engine;
	use ring::{digest, hmac, pbkdf2};
	use std::num::NonZeroU32;

	let salt_field = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("s="))
		.expect("s= in server-first");
	let salt = base64::engine::general_purpose::STANDARD
		.decode(salt_field)
		.expect("base64 salt");
	let iterations: u32 = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("i="))
		.expect("i= in server-first")
		.parse()
		.expect("iteration count");
	let combined_nonce = server_first
		.split(',')
		.find_map(|field| field.strip_prefix("r="))
		.expect("r= in server-first");
	let without_proof = format!("c=biws,r={combined_nonce}");
	// The bare client-first, without the GS2 header: it is what the
	// auth message is built from.
	let auth_message = format!("n=alice,r=CN,{server_first},{without_proof}");

	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(iterations).unwrap(),
		&salt,
		password.as_bytes(),
		&mut salted,
	);
	let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
	let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
	let client_sig = hmac::sign(
		&hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()),
		auth_message.as_bytes(),
	);
	let proof: Vec<u8> = client_key
		.as_ref()
		.iter()
		.zip(client_sig.as_ref())
		.map(|(a, b)| a ^ b)
		.collect();
	let server_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Server Key");
	let server_sig = hmac::sign(
		&hmac::Key::new(hmac::HMAC_SHA256, server_key.as_ref()),
		auth_message.as_bytes(),
	);
	Client {
		final_message: format!("{without_proof},p={}", b64_bytes(&proof)),
		server_final: format!("v={}", b64_bytes(server_sig.as_ref())),
	}
}

/// Drive the exchange up to the server-final challenge: the session,
/// what the client expects and what the server actually sent.
pub(in crate::smtp::session::tests::mods) fn at_server_final() -> (Session, Client, String) {
	let mut session = scram_session(true);
	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	let client = client_exchange(&server_first, fixtures::password());
	let action = session.auth_line(&b64(&client.final_message));
	// The server-final is a challenge, so the reply is a 334 whose
	// payload is the base64 of the server-final message.
	assert_eq!(reply_code(&action), 334);
	let server_final = decode_server_first(&scram_challenge_text(&action));
	(session, client, server_final)
}

/// The server-final travels as a challenge and the empty line closes
/// the exchange with the `235`.
#[test]
fn the_server_final_is_a_challenge_and_the_empty_line_closes_the_exchange() {
	let (mut session, _client, server_final) = at_server_final();
	assert!(
		server_final.starts_with("v="),
		"the challenge must carry the server-final, got {server_final}"
	);
	assert_eq!(
		session.authenticated(),
		None,
		"the session is not authenticated until the client acknowledges"
	);
	let action = session.auth_line("");
	assert_eq!(reply_code(&action), 235);
	assert_eq!(session.authenticated(), Some("alice"));
}

/// Without the empty line the session stays unauthenticated: the proof
/// alone does not open the session.
#[test]
fn without_the_empty_line_the_session_stays_unauthenticated() {
	let (session, _client, _server_final) = at_server_final();
	assert_eq!(
		session.authenticated(),
		None,
		"a proof without the acknowledgement must not authenticate"
	);
}

/// The challenge carries the very server-final the client verifies.
#[test]
fn the_challenge_carries_the_server_final_the_client_verifies() {
	let (_session, client, server_final) = at_server_final();
	assert_eq!(
		server_final, client.server_final,
		"the client must be able to verify its own signature against the challenge"
	);
}

/// A line other than the empty one in the acknowledgement round is a
/// protocol error: the session stays unauthenticated.
#[test]
fn a_line_other_than_the_empty_one_is_refused_without_authenticating() {
	let (mut session, _client, _server_final) = at_server_final();
	let action = session.auth_line("Tk9PUA==");
	assert_eq!(reply_code(&action), 501);
	assert_eq!(session.authenticated(), None);
}

/// The cancellation still works in the last round: `*` aborts the
/// exchange and leaves the session unauthenticated.
#[test]
fn the_cancellation_in_the_last_round_leaves_the_session_unauthenticated() {
	let (mut session, _client, _server_final) = at_server_final();
	let action = session.auth_line("*");
	assert_eq!(reply_code(&action), 501);
	assert_eq!(session.authenticated(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scram_requires_current_credentials_and_account_rules_at_each_final_round() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::base::FakeBanStore;
	use crate::smtp::scram::ScramStored;

	for before_proof in [true, false] {
		for mutation in 0..10 {
			let bans = Arc::new(FakeBanStore::new(BanPolicy::default()));
			let original = Arc::try_unwrap(super::tests_scram::scram_directory())
				.expect("unique directory")
				.with_ban_store(bans.clone());
			let mut session = scram_session(true).with_directory(Arc::new(original));
			session.set_peer_ip(Some("203.0.113.53".parse().expect("peer")));
			let challenge =
				session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
			assert_eq!(reply_code(&challenge), 334);
			let first = decode_server_first(&scram_challenge_text(&challenge));
			let client = client_exchange(&first, fixtures::password());
			let hash = session
				.directory
				.credentials("alice")
				.expect("password hash")
				.1
				.to_string();
			if !before_proof {
				assert_eq!(
					reply_code(&session.auth_line(&b64(&client.final_message))),
					334
				);
			}

			let current = Arc::try_unwrap(super::tests_scram::scram_directory())
				.expect("unique directory")
				.with_password_hashes([("alice".into(), hash)]);
			let current = match mutation {
				0 => Directory::default(),
				1 => current.with_disabled(["alice".into()]),
				2 => current.with_allowed_protocols([("alice".into(), vec![])]),
				3 => current.with_totp([("alice".into(), "JBSWY3DPEHPK3PXP".into())]),
				4 => current.with_password_hashes([("alice".into(), "changed hash".into())]),
				5 => current.with_scram([]),
				_ => {
					let mut credentials = current.scram_credentials("alice").expect("verifier");
					match mutation {
						6 => credentials.stored_key[0] ^= 1,
						7 => credentials.server_key[0] ^= 1,
						8 => credentials.salt[0] ^= 1,
						9 => credentials.iterations += 1,
						_ => unreachable!(),
					}
					current
						.with_scram([("alice".into(), ScramStored::from_credentials(&credentials))])
				}
			};
			session.set_directory_for_test(Arc::new(current.with_ban_store(bans.clone())));
			let response = if before_proof {
				session.auth_line(&b64(&client.final_message))
			} else {
				session.auth_line("")
			};
			assert_eq!(
				scram_challenge_text(&response),
				"535 5.7.8 authentication credentials invalid\r\n",
				"mutation={mutation}, before_proof={before_proof}"
			);
			assert_eq!(session.authenticated(), None);
			assert_eq!(session.auth_failures, 1);
			assert!(session.pending_scram.is_none());
			assert_eq!(bans.call_count("record_failure"), 3);
			assert_eq!(bans.call_count("clear_success"), 0);
		}
	}
}

#[test]
fn scram_accepts_an_equivalent_directory_snapshot() {
	let (mut session, _, _) = at_server_final();
	// A directory publication with unchanged credentials preserves the exchange.
	let hash = session
		.directory
		.credentials("alice")
		.expect("password hash")
		.1
		.to_string();
	let current = Arc::try_unwrap(super::tests_scram::scram_directory())
		.expect("unique directory")
		.with_password_hashes([("alice".into(), hash)]);
	session.set_directory_for_test(Arc::new(current));
	assert_eq!(reply_code(&session.auth_line("")), 235);
	assert_eq!(session.authenticated(), Some("alice"));
}
