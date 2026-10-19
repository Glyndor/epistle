//! Ban-owner-known-network tests at the directory level: the shared
//! gate that PLAIN/LOGIN/SCRAM all reach through
//! [`Directory::authenticate_verdict`]. The protocol-level tests live
//! in `session_tests_scram_ban_owner_known_network.rs` for the SMTP
//! session and in the IMAP/POP3/ManageSieve analogues; the assertions
//! here hold the shared contract together.

use std::net::IpAddr;

use super::Directory;
use super::gate_fixture::*;
use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::FakeBanStore;
use crate::config::Protocol;
use crate::smtp::directory::hash_gate::Verdict;
use crate::test_fixtures as fixtures;

fn directory_with(store: std::sync::Arc<FakeBanStore>) -> Directory {
	gate_directory().with_ban_store(store)
}

fn ip(text: &str) -> Option<IpAddr> {
	Some(text.parse().expect("address"))
}

fn verdict(directory: &Directory, login: &str, password: &str, from: &str) -> Verdict {
	directory.authenticate_verdict(login, password, ip(from), Protocol::Imaps)
}

fn admitted(directory: &Directory, login: &str, password: &str, from: &str) -> bool {
	matches!(
		verdict(directory, login, password, from),
		Verdict::Admitted { .. }
	)
}

/// A banned account from a network the owner has signed in from before
/// is admitted on a fresh PLAIN sign-in with the right credentials.
/// The test arms a ban on the account and a `(account, network)` row
/// on the bypass list, calls `authenticate_verdict` with the right
/// password, and asserts the verdict is `Admitted`. The audit event
/// for the ban is still emitted (the ban is not lifted, only the
/// single request bypassed), and the ban store's `clear_success` was
/// called for the account and the pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_admits_a_banned_account_from_a_known_network() {
	let store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	store.arm_ban(
		"account:alice",
		crate::antispam::bans::BanInfo {
			until_secs: u64::MAX,
			reason: "manual".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	store.arm_known_network("alice", "203.0.113.50", now);
	let directory = directory_with(store.clone());

	assert!(
		admitted(&directory, OPEN, fixtures::password(), "203.0.113.50"),
		"a banned account from a known network must be admitted with the right password"
	);
	assert!(
		store.call_count("clear_success") >= 2,
		"a successful sign-in must clear both the account and the pair rows: got {} clear_success calls",
		store.call_count("clear_success")
	);
	assert!(
		store
			.known_network_last_seen("alice", "203.0.113.50")
			.is_some(),
		"the success path must leave the (alice, network) row in the bypass list"
	);
}

/// A banned account from a network the owner has never signed in
/// from is refused exactly like a wrong-password sign-in: the verdict
/// is `Refused`, the credential check never ran (no hashing), and the
/// strike count does not move (a ban refusal never records). The
/// test arms an account ban and a bypass row for a network the test
/// does not connect from, then asserts the wire-equivalent outcome
/// from a fresh PLAIN sign-in attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_refuses_a_banned_account_from_an_unknown_network() {
	let store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	store.arm_ban(
		"account:alice",
		crate::antispam::bans::BanInfo {
			until_secs: u64::MAX,
			reason: "manual".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// Bypass row on an unrelated /64: the test connects from a
	// different address, so the bypass does not lift the ban.
	store.arm_known_network("alice", "198.51.100.5", now);
	let directory = directory_with(store.clone());

	assert_eq!(
		verdict(&directory, OPEN, fixtures::password(), "203.0.113.51"),
		Verdict::Refused,
		"a banned account from an unknown network must be refused with the same wire shape as a wrong password"
	);
	assert_eq!(
		store.call_count("record_failure"),
		0,
		"a ban refusal must not record a failure: got {} record_failure calls",
		store.call_count("record_failure")
	);
}

/// A banned account from a known network with the wrong credentials
/// produces the same wire shape as a wrong-password sign-in: the
/// ban is bypassed, the credential check runs, the verifier rejects,
/// the verdict is `Refused`, and a strike lands on the IP/pair/account
/// the same way any other failed sign-in lands. The unknown-network
/// path skips the hash work; the known-network path runs it, but the
/// oracle-free property is held by the verdict and the audit shape,
/// not by timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_refuses_a_banned_account_known_network_with_wrong_credentials() {
	let store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	store.arm_ban(
		"account:alice",
		crate::antispam::bans::BanInfo {
			until_secs: u64::MAX,
			reason: "manual".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	store.arm_known_network("alice", "203.0.113.52", now);
	let directory = directory_with(store.clone());

	assert_eq!(
		verdict(&directory, OPEN, fixtures::wrong_password(), "203.0.113.52"),
		Verdict::Refused,
		"a banned account from a known network with the wrong password must be refused like a wrong password"
	);
	assert!(
		store.call_count("record_failure") >= 3,
		"a wrong credential on a bypassed account must record a strike on the IP, pair, and account: got {} record_failure calls",
		store.call_count("record_failure")
	);
}

/// IPv6 clients are keyed by /64: a sign-in from any address in the
/// /64 puts the whole /64 on the bypass list, and a later sign-in
/// from a sibling address in the same /64 lifts the ban. The test
/// arms a ban on the account, arms the /64 row, and asserts a fresh
/// sign-in from a different host half in the same /64 succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_admits_a_banned_account_known_ipv6_slash_64() {
	let store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	store.arm_ban(
		"account:alice",
		crate::antispam::bans::BanInfo {
			until_secs: u64::MAX,
			reason: "manual".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// The /64 the bypass list stores: lower 64 bits zeroed.
	store.arm_known_network("alice", "2001:db8:1::", now);
	let directory = directory_with(store.clone());

	assert!(
		admitted(
			&directory,
			OPEN,
			fixtures::password(),
			"2001:db8:1::dead:beef"
		),
		"a banned account must be admitted from any host half in the /64 the owner signed in from"
	);
}

/// The window is enforced: a `(account, network)` row whose
/// `last_seen` is past the policy's known-network window does not
/// lift a fresh ban. The test arms a ban and arms the bypass row at
/// a timestamp well outside the 30-day window, then asserts a fresh
/// sign-in is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_refuses_a_banned_account_when_the_known_network_row_is_stale() {
	let store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	store.arm_ban(
		"account:alice",
		crate::antispam::bans::BanInfo {
			until_secs: u64::MAX,
			reason: "manual".to_string(),
		},
	);
	// A `last_seen` well outside the 30-day window: the bypass row
	// is treated as past its window by the lookup.
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	store.arm_known_network(
		"alice",
		"203.0.113.53",
		now.saturating_sub(60 * 60 * 24 * 60),
	);
	let directory = directory_with(store);

	assert_eq!(
		verdict(&directory, OPEN, fixtures::password(), "203.0.113.53"),
		Verdict::Refused,
		"a banned account from a network whose bypass row is past its lifetime must be refused"
	);
}

/// Fail-closed posture: a database error during `is_known_network`
/// keeps the ban enforced. The test arms a ban and arms the
/// `next_is_known_network_fails` arming on the fake, then asserts a
/// fresh sign-in is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_fail_closed_when_known_network_lookup_errors() {
	let store =
		std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()).fail_next_is_known_network());
	store.arm_ban(
		"account:alice",
		crate::antispam::bans::BanInfo {
			until_secs: u64::MAX,
			reason: "manual".to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	store.arm_known_network("alice", "203.0.113.54", now);
	let directory = directory_with(store);

	assert_eq!(
		verdict(&directory, OPEN, fixtures::password(), "203.0.113.54"),
		Verdict::Refused,
		"a database error during the known-network check must keep the ban enforced"
	);
}

/// A ban an operator placed by hand is not bypassed, even from a network
/// the owner has signed in from before and with the right password.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_manual_ban_is_not_bypassed_from_a_known_network() {
	let store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	store.arm_ban(
		"account:alice",
		crate::antispam::bans::BanInfo {
			until_secs: u64::MAX,
			reason: crate::antispam::bans::MANUAL_REASON.to_string(),
		},
	);
	let now: u64 = std::time::SystemTime::now()
		.duration_since(std::time::SystemTime::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	store.arm_known_network("alice", "203.0.113.50", now);
	let directory = directory_with(store.clone());
	assert!(
		!admitted(&directory, OPEN, fixtures::password(), "203.0.113.50"),
		"a ban placed by an operator must hold from a known network"
	);
}
