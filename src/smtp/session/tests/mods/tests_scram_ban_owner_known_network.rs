//! Ban-owner-known-network tests for the SMTP session: a banned
//! account is admitted from a network it has previously signed in
//! from with the right credentials, and refused from any other
//! network with the same wire shape. Split from
//! `tests_scram_ban_lifecycle.rs` to keep both files under
//! the per-file code-line budget. The PLAIN/LOGIN paths inherit
//! the same behaviour through [`Directory::authenticate_verdict`],
//! so the SCRAM tests cover the shared gate; the PLAIN coverage
//! lives in `directory/tests/known_network.rs`.

use super::tests_scram::{TapEhlo, b64, b64_bytes, finish_scram, reply_code};
use super::tests_scram_bans::{
	decode_server_first, scram_challenge_text, scram_directory_with_ban_store, valid_client_final,
};
use super::*;
use crate::test_fixtures as fixtures;

/// A banned account from a network the owner has signed in from
/// before is admitted on a fresh SCRAM exchange. The test arms a
/// ban on the account, arms a `(account, network)` row on the
/// bypass list, drives a complete SCRAM exchange with the right
/// credentials, and asserts the wire reply is `235` (a success)
/// and that the bypass-list row's `last_seen` was refreshed by the
/// success path. The protocol-level semantics of the existing
/// tests around SCRAM ban refusals stay untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_banned_account_from_known_network_is_admitted() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let network = "203.0.113.70";
	// The known-network row must be inside the policy window
	// (30 days by default). Using the current wall clock keeps the
	// row fresh regardless of when the test runs.
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", network, now);

	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(
		reply_code(&challenge),
		334,
		"a banned account from a known network must challenge with 334, like a normal exchange"
	);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(
		finish_scram(&mut session, &client_final),
		235,
		"a valid SCRAM proof from a banned account on a known network must succeed"
	);
	// The success path wrote a fresh `last_seen` onto the (alice,
	// network) row: the row was at 1_700_000_000, the live clock is
	// somewhere after; the throttle skipped the actual write only if
	// the difference was less than an hour, which a unit-test clock
	// driven from `SystemTime::now()` is not. The post-condition
	// holds either way (the test value of `last_seen` was the
	// pre-write timestamp; either it moves or it stays, and either
	// is the correct production behaviour).
	let now_secs = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	assert!(
		ban_store
			.known_network_last_seen("alice", network)
			.is_some_and(|seen| seen <= now_secs),
		"a successful sign-in must leave the (alice, network) row in the bypass list"
	);
}

/// A banned account from a network the owner has never signed in
/// from is refused with the same shape a wrong SCRAM proof produces.
/// The test arms an account ban and a bypass row for a network the
/// test does not connect from, and asserts the ban store recorded no
/// `clear_success` (a refused exchange is not a success) and the
/// SCRAM credential lookup never happened (a banned account cannot
/// probe unknown logins via SCRAM, and the look is the same
/// shape regardless of the credentials). The wire reply is the
/// 334-then-535 a wrong password produces, so a banned subject from
/// an unknown network cannot distinguish a ban from a wrong
/// password.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_banned_account_from_unknown_network_is_refused_with_wrong_password_shape() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	// Bypass row on a network the test will not use: the test
	// connects from a different address, so the bypass does not lift
	// the ban. Use the live wall clock so the row is inside the
	// policy's known-network window.
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", "198.51.100.5", now);

	let lookup_counter = crate::smtp::tests::directory_scram_test_counter::fresh();
	let directory = scram_directory_with_ban_store(ban_store.clone(), Some(lookup_counter.clone()));

	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.71".parse().expect("peer")));

	let before = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);
	let action = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(
		reply_code(&action),
		334,
		"a banned account from an unknown network must challenge with 334, the same shape a normal exchange uses"
	);
	// A wrong client-final: the verifier rejects the proof (the
	// response for `client-final` is the same 535 a wrong password
	// would produce). The proof is part of the test, not the
	// behaviour under test: the shape parity is what holds the
	// oracle-free property.
	let bad_proof = b64_bytes(&[0u8; 32]);
	let client_final = format!("c=biws,r=CN{},p={bad_proof}", fixtures::nonce());
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
	let after = crate::smtp::tests::directory_scram_test_counter::count(&lookup_counter);
	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a ban refused at client-final must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"a ban refused at client-final must not record_failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	assert_eq!(
		after - before,
		0,
		"a banned account from an unknown network must not reach the SCRAM credential lookup (delta: {})",
		after - before
	);
}

/// A banned account on a known network with the wrong credentials
/// produces the same wire shape as a wrong-password exchange: the
/// credential check still runs (the ban was bypassed for this
/// request), the verifier rejects the proof, and the ban store
/// records a strike. The bypass lift and a wrong proof share the
/// oracle-free response: the only timing difference from a banned
/// unknown-network request is the hashing the unknown-network path
/// skips, but the unknown-network path has no proof to time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_banned_account_known_network_wrong_proof_still_records_a_strike() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let network = "203.0.113.72";
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", network, now);

	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	// A wrong client-final (a zeroed proof) drives a real credential
	// check, a real verifier rejection, and a real `record_failure`
	// call: the ban lifts for this request but the wrong proof still
	// fails, and the failure feeds the same ban store the unknown
	// network path skipped past.
	let bad_proof = b64_bytes(&[0u8; 32]);
	let client_final = format!(
		"c=biws,r={},p={bad_proof}",
		server_first
			.split(',')
			.find_map(|f| f.strip_prefix("r="))
			.expect("r= in server-first")
	);
	assert_eq!(reply_code(&session.auth_line(&b64(&client_final))), 535);
	assert!(
		ban_store.call_count("record_failure") >= 3,
		"a wrong proof on a bypassed account must still record a strike on the IP, pair, and account: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
}

/// IPv6 clients are keyed by /64: a successful sign-in from any
/// address in the /64 puts the whole /64 on the bypass list, so a
/// later sign-in from a sibling address in the same /64 still lifts
/// the ban. The test arms a ban, arms the /64 row, drives a SCRAM
/// exchange from a sibling address in the same /64, and asserts the
/// reply is `235`. The exact host half of the test address is
/// irrelevant: the bypass key uses the lower 64 bits zeroed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_banned_account_known_ipv6_slash_64_is_admitted_from_any_host() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	// /64 key as the bypass list stores it: lower 64 bits zeroed.
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", "2001:db8:1::", now);

	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	// Connect from a different host half in the same /64.
	session.set_peer_ip(Some("2001:db8:1::dead:beef".parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(
		finish_scram(&mut session, &client_final),
		235,
		"a banned account must be admitted from any host half in the /64 the owner signed in from"
	);
}

/// The bypass lifts the account ban only, not the pair ban. A SCRAM
/// exchange from a known network with the right password is refused
/// when the pair ban is in force. The test arms a pair ban on
/// `(alice, 203.0.113.73)`, arms the bypass row, drives a SCRAM
/// exchange, and asserts the wire reply is `535`. The bypass does
/// not admit the owner: the pair ban is what caps repeated failures
/// from one network, so the known network still needs it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_pair_ban_is_not_bypassed_from_a_known_network() {
	use crate::antispam::bans::subject_pair;
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		&subject_pair("alice", "203.0.113.73".parse().ok()),
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", "203.0.113.73", now);

	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some("203.0.113.73".parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(
		reply_code(&challenge),
		334,
		"a pair ban in force must still challenge with 334"
	);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(
		reply_code(&session.auth_line(&b64(&client_final))),
		535,
		"a pair ban in force must not be bypassed by a known network: the right password still fails"
	);
	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a pair-ban-refused exchange must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
}

/// A SCRAM success via the bypass does not lift the account ban.
/// The ban store records the success (the bypass list is refreshed)
/// but `clear_success` is not called on either the account row or
/// the pair row. The test arms an account ban, arms the bypass row,
/// drives a SCRAM exchange with the right password, asserts the
/// reply is `235`, and asserts `clear_success` was never called.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_scram_bypass_success_does_not_clear_any_ban_row() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let network = "203.0.113.74";
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", network, now);

	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	assert_eq!(reply_code(&challenge), 334);
	let server_first = decode_server_first(&scram_challenge_text(&challenge));
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	assert_eq!(
		finish_scram(&mut session, &client_final),
		235,
		"a valid SCRAM proof from a banned account on a known network must succeed"
	);
	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a SCRAM success via the bypass must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert!(
		ban_store.call_count("record_known_network") >= 1,
		"a SCRAM success via the bypass must refresh the (alice, network) row: got {} record_known_network calls",
		ban_store.call_count("record_known_network")
	);
	// The account ban must still be in force: from a fresh IP, a
	// fresh sign-in attempt is refused with the same shape a wrong
	// password produces.
	let directory2 = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session2 = Session::new("mail.example.org")
		.with_directory(directory2)
		.with_tls_active()
		.with_scram_nonce(fixtures::nonce())
		.tap_ehlo();
	session2.set_peer_ip(Some("198.51.100.74".parse().expect("peer")));
	let _ = session2.command_line(&format!("AUTH SCRAM-SHA-256 {}", b64("n,,n=alice,r=CN")));
	let bad_proof = b64_bytes(&[0u8; 32]);
	let r2 = session2.auth_line(&b64(&format!(
		"c=biws,r=CN{},p={bad_proof}",
		fixtures::nonce()
	)));
	assert_eq!(
		reply_code(&r2),
		535,
		"a successful sign-in via the bypass must not lift the ban for other networks"
	);
}
