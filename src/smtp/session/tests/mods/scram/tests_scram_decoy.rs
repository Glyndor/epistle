//! A SCRAM client-first for a login nobody holds gets the same challenge as one
//! for a real account, so the exchange cannot be used to find out which
//! accounts exist.

use super::tests_scram::{b64, reply_code};
use super::tests_scram_bans::{decode_server_first, scram_challenge_text};
use super::*;
use crate::smtp::directory::gate_fixture::*;
use crate::smtp::scram::SCRAM_ITERATIONS;
use crate::test_fixtures as fixtures;

fn session() -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(Arc::new(directory_with_production_verifier()))
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce());
	session.command_line("EHLO client.example.org");
	session
}

/// The server-first the server answers to a client-first for `user`.
fn challenge(session: &mut Session, user: &str) -> Option<String> {
	let action = session.command_line(&format!(
		"AUTH SCRAM-SHA-256 {}",
		b64(&format!("n,,n={user},r=CN"))
	));
	(reply_code(&action) == 334).then(|| decode_server_first(&scram_challenge_text(&action)))
}

#[test]
fn an_unknown_login_gets_a_challenge_shaped_like_a_real_one() {
	let real = challenge(&mut session(), OPEN).expect("real account is challenged");
	let ghost = challenge(&mut session(), "ghost").expect("unknown login must be challenged too");
	let (real_salt, real_iterations) = salt_and_iterations(&real);
	let (ghost_salt, ghost_iterations) = salt_and_iterations(&ghost);
	assert_eq!(real_iterations, SCRAM_ITERATIONS);
	assert_eq!(ghost_iterations, real_iterations);
	assert_eq!(ghost_salt.len(), real_salt.len());
	assert!(
		ghost.starts_with("r=CN"),
		"the nonce is echoed like a real one"
	);
}

#[test]
fn the_salt_of_an_unknown_login_repeats_and_differs_between_logins() {
	let first = challenge(&mut session(), "ghost").expect("challenge");
	let again = challenge(&mut session(), "ghost").expect("challenge");
	let other = challenge(&mut session(), "phantom").expect("challenge");
	assert_eq!(salt_and_iterations(&first).0, salt_and_iterations(&again).0);
	assert_ne!(salt_and_iterations(&first).0, salt_and_iterations(&other).0);
}

#[test]
fn an_unknown_login_ends_as_a_wrong_proof() {
	let mut session = session();
	let server_first = challenge(&mut session, "ghost").expect("challenge");
	let client_final = scram_client_final("n=ghost,r=CN", &server_first, fixtures::password());
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
	assert_eq!(session.authenticated(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_login_costs_the_peer_one_strike_when_the_exchange_ends() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::base::FakeBanStore;
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = directory_with_production_verifier().with_ban_store(ban_store.clone());
	let mut session = Session::new("mail.example.org")
		.with_directory(Arc::new(directory))
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce());
	session.command_line("EHLO client.example.org");
	session.set_peer_ip(Some("203.0.113.77".parse().expect("peer")));
	let server_first = challenge(&mut session, "ghost").expect("challenge");
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"nothing is counted before the proof"
	);
	let client_final = scram_client_final("n=ghost,r=CN", &server_first, fixtures::password());
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
	// One strike on the peer; the stand-in pair and account an unknown login is
	// counted under (so it writes what a real one does) make the other two.
	assert_eq!(ban_store.call_count("record_failure"), 3);
	assert_eq!(ban_store.failure_count("ip:203.0.113.77", 0), 1);
}
