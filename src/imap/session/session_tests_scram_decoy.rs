//! An IMAP SCRAM client-first for a login nobody holds gets the same
//! continuation as one for a real account.

use super::*;
use crate::smtp::directory::gate_fixture::*;
use crate::smtp::scram::SCRAM_ITERATIONS;
use crate::test_fixtures as fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn session(dir: &std::path::Path) -> Session {
	Session::new(
		"mail.example.org",
		dir.to_path_buf(),
		Arc::new(directory_with_production_verifier()),
	)
	.with_scram_nonce(fixtures::nonce())
}

/// The server-first the server answers to a client-first for `user`.
fn challenge(session: &mut Session, user: &str) -> Option<String> {
	let out = text(&session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode(format!("n,,n={user},r=CN"))
	)));
	let encoded = out.strip_prefix("+ ")?;
	Some(String::from_utf8(B64.decode(encoded.trim()).expect("base64")).expect("utf8"))
}

#[test]
fn an_unknown_login_gets_a_continuation_shaped_like_a_real_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let real = challenge(&mut session(dir.path()), OPEN).expect("real account is challenged");
	let ghost =
		challenge(&mut session(dir.path()), "ghost").expect("unknown login must be challenged too");
	let (real_salt, real_iterations) = salt_and_iterations(&real);
	let (ghost_salt, ghost_iterations) = salt_and_iterations(&ghost);
	assert_eq!(real_iterations, SCRAM_ITERATIONS);
	assert_eq!(ghost_iterations, real_iterations);
	assert_eq!(ghost_salt.len(), real_salt.len());
}

#[test]
fn the_salt_of_an_unknown_login_repeats_and_differs_between_logins() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = challenge(&mut session(dir.path()), "ghost").expect("challenge");
	let again = challenge(&mut session(dir.path()), "ghost").expect("challenge");
	let other = challenge(&mut session(dir.path()), "phantom").expect("challenge");
	assert_eq!(salt_and_iterations(&first).0, salt_and_iterations(&again).0);
	assert_ne!(salt_and_iterations(&first).0, salt_and_iterations(&other).0);
}

#[test]
fn an_unknown_login_ends_as_a_wrong_proof() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = session(dir.path());
	let server_first = challenge(&mut session, "ghost").expect("challenge");
	let client_final = scram_client_final("n=ghost,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(client_final)));
	assert!(out.contains("a NO"), "{out}");
	assert_eq!(session.account(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_login_costs_the_peer_one_strike_when_the_exchange_ends() {
	use crate::antispam::bans::BanPolicy;
	use crate::antispam::bans::tests::FakeBanStore;
	let dir = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	let directory = directory_with_production_verifier().with_ban_store(ban_store.clone());
	let mut session = Session::new(
		"mail.example.org",
		dir.path().to_path_buf(),
		Arc::new(directory),
	)
	.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some("203.0.113.78".parse().expect("peer")));
	let server_first = challenge(&mut session, "ghost").expect("challenge");
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"nothing is counted before the proof"
	);
	let client_final = scram_client_final("n=ghost,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(client_final)));
	assert!(out.contains("a NO"), "{out}");
	// One strike on the peer; the stand-in pair and account an unknown login is
	// counted under (so it writes what a real one does) make the other two.
	assert_eq!(ban_store.call_count("record_failure"), 3);
	assert_eq!(ban_store.failure_count("ip:203.0.113.78", 0), 1);
}
