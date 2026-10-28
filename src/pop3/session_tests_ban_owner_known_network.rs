//! Ban-owner-known-network tests for the POP3 session. The POP3
//! password path reaches the same [`Directory::authenticate_verdict`]
//! the SMTP submission, IMAP, ManageSieve, API and WebDAV paths
//! reach, so the assertions here hold the POP3-specific surface:
//! the `USER`/`PASS` command pair and the ban store's per-method
//! counters. Split from `session_tests.rs` to keep both files under
//! the per-file code-line budget.

use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::FakeBanStore;
use crate::directory_store::DirectoryHandle;
use crate::pop3::backend::MailboxBackend;
use crate::pop3::command::Command;
use crate::pop3::session::{Response, Session};
use crate::smtp::auth::tests::base::fixture_password;
use std::collections::HashMap;

/// A POP3 sign-in from a banned account whose network is on the
/// bypass list is admitted with the right password. The test arms an
/// account ban, arms the `(alice, network)` row on the bypass list,
/// drives `USER` + `PASS` with the right password, and asserts the
/// wire reply is `Response::Ok`. The success path refreshes the
/// bypass list (`record_known_network` is called and the row's
/// `last_seen` is non-None), but it does not call `clear_success`
/// on the account or pair row: the ban stays in force for any
/// other network the attacker might use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pop3_banned_account_from_known_network_is_admitted() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
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
	ban_store.arm_known_network("alice", "203.0.113.30", now);

	let directory = crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes(HashMap::from([(
		"alice".to_string(),
		crate::smtp::auth::tests::base::hash(fixture_password()),
	)]))
	.with_ban_store(ban_store.clone());
	let backend = MailboxBackend::new(DirectoryHandle::new(directory), tmp.path().to_path_buf());

	let peer: std::net::IpAddr = "203.0.113.30".parse().expect("peer");
	let mut session = Session::new(backend);
	session.set_peer_ip(Some(peer));
	let _ = session.greeting();
	assert!(matches!(
		session.handle(Command::User("alice@example.org".into())),
		Response::Ok(_)
	));
	assert!(matches!(
		session.handle(Command::Pass(fixture_password().into())),
		Response::Ok(_)
	));
	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a successful POP3 sign-in via the bypass must not clear_success the account or the pair: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
	assert!(
		ban_store.call_count("record_known_network") >= 1,
		"a successful POP3 sign-in via the bypass must refresh the (alice, network) row: got {} record_known_network calls",
		ban_store.call_count("record_known_network")
	);
	assert!(
		ban_store
			.known_network_last_seen("alice", "203.0.113.30")
			.is_some(),
		"the success path must leave the (alice, network) row in the bypass list"
	);
}

/// A POP3 sign-in from a banned account on an unknown network is
/// refused with `Response::Err("authentication failed")`, the same
/// shape a wrong password produces. The ban store's `record_failure`
/// count does not move (a ban refusal never moves the strike count),
/// and `clear_success` is not called (a refused exchange is not a
/// success). The wire shape parity with a wrong password is what
/// holds the oracle-free property.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pop3_banned_account_from_unknown_network_is_refused() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let ban_store = std::sync::Arc::new(FakeBanStore::new(BanPolicy::default()));
	ban_store.arm_ban(
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
	// Bypass row on an unrelated network: the test connects from a
	// different address, so the bypass does not lift the ban.
	ban_store.arm_known_network("alice", "198.51.100.30", now);

	let directory = crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes(HashMap::from([(
		"alice".to_string(),
		crate::smtp::auth::tests::base::hash(fixture_password()),
	)]))
	.with_ban_store(ban_store.clone());
	let backend = MailboxBackend::new(DirectoryHandle::new(directory), tmp.path().to_path_buf());

	let peer: std::net::IpAddr = "203.0.113.31".parse().expect("peer");
	let mut session = Session::new(backend);
	session.set_peer_ip(Some(peer));
	let _ = session.greeting();
	assert!(matches!(
		session.handle(Command::User("alice@example.org".into())),
		Response::Ok(_)
	));
	assert_eq!(
		session.handle(Command::Pass(fixture_password().into())),
		Response::Err("authentication failed".to_string()),
		"a banned account from an unknown network must be refused with the same shape a wrong password produces"
	);
	assert_eq!(
		ban_store.call_count("record_failure"),
		0,
		"a ban refusal must not record a failure: got {} record_failure calls",
		ban_store.call_count("record_failure")
	);
	assert_eq!(
		ban_store.call_count("clear_success"),
		0,
		"a ban refusal must not clear_success: got {} clear_success calls",
		ban_store.call_count("clear_success")
	);
}
