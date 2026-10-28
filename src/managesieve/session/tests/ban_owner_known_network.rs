//! Ban-owner-known-network tests for the ManageSieve session. The
//! ManageSieve authentication path reaches the same
//! [`Directory::authenticate_with_ip`] the SMTP submission, IMAP,
//! POP3, API and WebDAV paths reach, so the assertions here hold the
//! ManageSieve-specific surface: the `AUTHENTICATE PLAIN` command
//! and the ban store's per-method counters. Split from
//! `base.rs` to keep both files under the per-file
//! code-line budget.

use crate::antispam::bans::BanPolicy;
use crate::antispam::bans::tests::FakeBanStore;
use crate::managesieve::command::Command;
use crate::managesieve::session::{Backend, Response, ScriptStore, Session};
use crate::smtp::auth::tests::base::fixture_password;
use std::collections::HashMap;
use std::path::PathBuf;

/// Backend that routes credential verification through the live
/// directory (the production shape), keeping `store` for the
/// in-memory script storage the session needs afterwards.
struct DirBackend {
	directory: std::sync::Arc<crate::smtp::directory::Directory>,
	accounts_root: PathBuf,
}

impl Backend for DirBackend {
	fn verify(
		&self,
		authcid: &str,
		password: &str,
		peer_ip: Option<std::net::IpAddr>,
	) -> Option<String> {
		self.directory.authenticate_with_ip(
			authcid,
			password,
			peer_ip,
			crate::config::Protocol::ManageSieve,
		)
	}
	fn store(&self, account: &str) -> ScriptStore {
		ScriptStore::new(&self.accounts_root, account)
	}
}

/// Encode `\0authcid\0password` for SASL PLAIN initial response.
fn sasl_plain_initial(authcid: &str, password: &str) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(format!("\0{authcid}\0{password}"))
}

/// A ManageSieve sign-in from a banned account whose network is on
/// the bypass list is admitted with the right password. The test
/// arms an account ban, arms the `(alice, network)` row on the
/// bypass list, drives `AUTHENTICATE PLAIN` with the right
/// credentials, and asserts the wire reply is `Response::Ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managesieve_banned_account_from_known_network_is_admitted() {
	let dir = tempfile::tempdir().expect("tempdir");
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
	ban_store.arm_known_network("alice", "203.0.113.60", now);

	let directory = std::sync::Arc::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::base::hash(fixture_password()),
		)]))
		.with_ban_store(ban_store.clone()),
	);
	let backend = DirBackend {
		directory,
		accounts_root: PathBuf::from(dir.path()),
	};
	let mut session = Session::new(backend, true);
	session.set_peer_ip(Some("203.0.113.60".parse().expect("peer")));
	let good = sasl_plain_initial("alice@example.org", fixture_password());
	let response = session.handle(Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: Some(good),
	});
	assert!(
		matches!(response, Response::Ok(_)),
		"a banned account from a known network must be admitted with the right password: got {response:?}"
	);
}

/// A ManageSieve sign-in from a banned account on an unknown network
/// is refused with the same shape a wrong password produces: the
/// reply is `Response::No`. The ban store's `record_failure` count
/// does not move (a ban refusal never moves the strike count), and
/// `clear_success` is not called.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managesieve_banned_account_from_unknown_network_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
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
	// Bypass row on an unrelated network.
	ban_store.arm_known_network("alice", "198.51.100.60", now);

	let directory = std::sync::Arc::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::base::hash(fixture_password()),
		)]))
		.with_ban_store(ban_store.clone()),
	);
	let backend = DirBackend {
		directory,
		accounts_root: PathBuf::from(dir.path()),
	};
	let mut session = Session::new(backend, true);
	session.set_peer_ip(Some("203.0.113.61".parse().expect("peer")));
	let good = sasl_plain_initial("alice@example.org", fixture_password());
	let response = session.handle(Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: Some(good),
	});
	assert!(
		matches!(response, Response::No(_)),
		"a banned account from an unknown network must refuse with NO: got {response:?}"
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
