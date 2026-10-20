//! Ban-owner-known-network tests for the IMAP session. The shared
//! gate that IMAP AUTHENTICATE reaches is the same
//! [`Directory::authenticate_verdict`] the SMTP session uses, so
//! the assertions here hold the IMAP-specific surface: the
//! AUTHENTICATE continuation, the LOGIN command, and the ban
//! store's per-method counters.
//!
//! Split from `session_tests_auth_ban_lifecycle.rs` to keep both
//! files under the per-file code-line budget.

use super::auth_bans::{scram_directory_with_ban_store, valid_client_final};
use super::text;
use super::*;
use crate::test_fixtures as fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// An IMAP AUTHENTICATE SCRAM exchange from a banned account whose
/// network is on the bypass list succeeds. The test arms an account
/// ban, arms the (alice, network) row on the bypass list, drives a
/// full SCRAM exchange with the right password, and asserts the
/// wire reply ends in `a OK`. The IMAP continuation rules mean the
/// ban shows up as a `+` challenge followed by `a NO` on the
/// `client-final` for a ban refusal; on a bypass the same `+`
/// is followed by `a OK`, which is the oracle-free outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_banned_account_from_known_network_is_admitted() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let network = "203.0.113.80";
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", network, now);

	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation challenge");
	// Decode the server-first; the SCRAM proof builder uses the
	// nonce from the server-first, not the static test nonce.
	let server_first = super::auth_bans::decode_server_first(&text(&challenge));
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(
		out.contains("a OK"),
		"a valid SCRAM proof from a banned account on a known network must succeed: {out}"
	);
}

/// An IMAP AUTHENTICATE SCRAM exchange from a banned account on an
/// unknown network is refused with the same shape a wrong password
/// produces: `+`-challenge then `a NO`. The lookup counter that the
/// directory maintains does not move, so a banned account cannot
/// probe unknown logins via IMAP SCRAM either. The ban store's
/// `clear_success` was not called (a refused exchange is not a
/// success), and the `record_failure` count is zero (a ban refusal
/// never moves the strike count).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_banned_account_from_unknown_network_is_refused() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// Bypass row on a network the test does not use.
	ban_store.arm_known_network("alice", "198.51.100.10", now);

	let lookup_counter = crate::smtp::directory_scram_test_counter::fresh();
	let directory = scram_directory_with_ban_store(ban_store.clone(), Some(lookup_counter.clone()));
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some("203.0.113.81".parse().expect("peer")));

	let before = crate::smtp::directory_scram_test_counter::count(&lookup_counter);
	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation challenge");
	// A wrong client-final: the verifier rejects the proof (the
	// server stores decoy credentials for a banned exchange, so
	// the proof cannot match). The wire reply is `a NO`, the same
	// shape a wrong password produces.
	let bad_proof = B64.encode(vec![0u8; 32]);
	let out =
		text(&session.auth_response(&format!("c=biws,r=CN{},p={bad_proof}", fixtures::nonce())));
	assert!(
		out.contains("a NO"),
		"a banned account from an unknown network must refuse with `a NO`: {out}"
	);
	let after = crate::smtp::directory_scram_test_counter::count(&lookup_counter);
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

/// An IMAP AUTHENTICATE SCRAM exchange from a banned account on a
/// known IPv6 /64 succeeds from any host half in the /64. The test
/// arms the /64 row on the bypass list and connects from a
/// different host half in the same /64, asserting the bypass lift
/// holds across the `/64` boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_banned_account_known_ipv6_slash_64_is_admitted() {
	use crate::antispam::bans::tests::FakeBanStore;
	use crate::antispam::bans::{BanInfo, BanPolicy};

	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	ban_store.arm_known_network("alice", "2001:db8:2::", now);

	let directory = scram_directory_with_ban_store(ban_store.clone(), None);
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	// Different host half, same /64.
	session.set_peer_ip(Some("2001:db8:2::dead:beef".parse().expect("peer")));

	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation challenge");
	let server_first = super::auth_bans::decode_server_first(&text(&challenge));
	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(
		out.contains("a OK"),
		"a banned account must be admitted from any host half in the /64 the owner signed in from: {out}"
	);
}
