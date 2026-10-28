//! TOCTOU regression tests for the IMAP SCRAM known-network bypass:
//! between the client-first and the client-final, the ban store may
//! be armed (a ban fires) or disarmed (a ban lapses). The flag that
//! drives the success path has to come from the recheck at
//! client-final, not from a value computed at client-first and
//! carried through the session state. The three tests below drive
//! the exchange by steps so the test can change the ban store in
//! between, the same shape the existing
//! `imap_scram_client_final_rechecks_ban` test uses.
//!
//! (a) account had no ban at client-first, a ban is armed between the
//!     two messages, the network is known, a valid proof authenticates
//!     and the account ban stays in force (a bypass lift must keep the
//!     row).
//! (b) account had a ban and a bypass row at client-first, the ban
//!     lapses between the two messages, a valid proof authenticates
//!     and the success path clears the rows (a normal lift).
//! (c) account had no ban at client-first, a ban is armed between the
//!     two messages, the network is unknown, a valid proof is
//!     refused (a ban that fires in flight rejects).
//!
//! Split from `auth_ban_owner_known_network.rs` to keep
//! that file under the per-file code-line budget.

use super::auth_bans::{decode_server_first, scram_directory_with_ban_store, valid_client_final};
use super::text;
use super::*;
use crate::antispam::bans::tests::FakeBanStore;
use crate::antispam::bans::{BanInfo, BanPolicy, BanStore};
use crate::test_fixtures as fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn far_future_ban(reason: &str) -> BanInfo {
	BanInfo {
		until_secs: u64::MAX,
		reason: reason.to_string(),
	}
}

fn now_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

async fn is_account_banned(store: &FakeBanStore, account: &str, now: u64) -> bool {
	let subject = format!("account:{account}");
	tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(store.is_banned(&subject, now))
	})
	.is_some()
}

/// (a) client-first is clean (no ban), a ban is armed between the two
/// messages, the network is on the bypass list, a valid proof lets the
/// owner in. The ban row must still be in force at the end: the bypass
/// lift at client-final only refreshes the network row, it must not
/// `clear_success` the ban that fired in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_bypass_toctou_ban_appears_in_flight_keeps_ban() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = FakeBanStore::new(BanPolicy::default());
	let ban_store_arc: std::sync::Arc<dyn crate::antispam::bans::BanStore> =
		std::sync::Arc::new(ban_store.clone());
	let network = "203.0.113.93";
	let now = now_secs();
	ban_store.arm_known_network("alice", network, now);

	let directory = scram_directory_with_ban_store(ban_store_arc.clone(), None);
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation challenge");
	let server_first = decode_server_first(&text(&challenge));
	ban_store.arm_ban(
		"account:alice",
		far_future_ban("5 failed authentications in 900 seconds"),
	);

	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(
		out.contains("a OK"),
		"a valid SCRAM proof from a known network must succeed even when a ban fires in flight: {out}",
	);

	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a bypass lift must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert!(
		is_account_banned(&ban_store, "alice", now_secs()).await,
		"the account ban that fired in flight must still be in force",
	);
}

/// (b) client-first already has a ban and a bypass row, but the ban
/// lapses between the two messages. A valid proof must succeed and the
/// success path must `clear_success` both the pair and the account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_bypass_toctou_ban_lapses_in_flight_lifts_ban() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = FakeBanStore::new(BanPolicy::default());
	let ban_store_arc: std::sync::Arc<dyn crate::antispam::bans::BanStore> =
		std::sync::Arc::new(ban_store.clone());
	let network = "203.0.113.94";
	let now = now_secs();
	ban_store.arm_known_network("alice", network, now);
	ban_store.arm_ban(
		"account:alice",
		far_future_ban("5 failed authentications in 900 seconds"),
	);

	let directory = scram_directory_with_ban_store(ban_store_arc.clone(), None);
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation challenge");
	let server_first = decode_server_first(&text(&challenge));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: 0,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);

	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(
		out.contains("a OK"),
		"a valid SCRAM proof after the ban lapses must succeed as a normal login: {out}",
	);

	assert_eq!(
		ban_store.call_count("clear_success"),
		2,
		"a ban that lapsed in flight must lift just like a normal success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert!(
		!is_account_banned(&ban_store, "alice", now_secs()).await,
		"the account ban that lapsed in flight must be gone after a successful login"
	);
}

/// (c) client-first is clean, a ban is armed in flight, the network is
/// not on the bypass list. A valid proof is refused: the recheck at
/// client-final sees a `Banned` outcome (no bypass), so the success
/// path never runs and the ban store receives no `record_failure` and
/// no `clear_success`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_scram_toctou_ban_appears_in_flight_unknown_network_rejects() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = FakeBanStore::new(BanPolicy::default());
	let ban_store_arc: std::sync::Arc<dyn crate::antispam::bans::BanStore> =
		std::sync::Arc::new(ban_store.clone());
	let network = "203.0.113.95";
	// No bypass row, so the recheck must answer `Banned`, not
	// `BannedButKnown`.
	let directory = scram_directory_with_ban_store(ban_store_arc.clone(), None);
	let mut session = Session::new("mail.example.org", tmp.path().to_path_buf(), directory)
		.with_scram_nonce(fixtures::nonce());
	session.set_peer_ip(Some(network.parse().expect("peer")));

	let challenge = session.command_line(&format!(
		"a AUTHENTICATE SCRAM-SHA-256 {}",
		B64.encode("n,,n=alice,r=CN")
	));
	assert!(challenge.collect_auth, "expected a continuation challenge");
	let server_first = decode_server_first(&text(&challenge));
	ban_store.arm_ban(
		"account:alice",
		BanInfo {
			until_secs: u64::MAX,
			reason: "5 failed authentications in 900 seconds".to_string(),
		},
	);

	let client_final = valid_client_final("n=alice,r=CN", &server_first, fixtures::password());
	let out = text(&session.auth_response(&B64.encode(&client_final)));
	assert!(
		out.contains("a NO"),
		"a ban that fires in flight on an unknown network must refuse: {out}",
	);
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
	assert!(
		is_account_banned(&ban_store, "alice", now_secs()).await,
		"the ban that fired in flight must still be in force on an unknown network"
	);
}
