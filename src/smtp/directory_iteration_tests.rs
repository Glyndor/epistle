//! Tests for SCRAM iteration-count defaults and the transparent upgrade on
//! successful cleartext authentication.
//!
//! Split into a sibling so `directory.rs` stays under the per-file
//! code-line budget. The tests exercise `ScramStored::with_fresh_salt`
//! (the value the directory feeds into the directory snapshot) and the
//! upgrade path wired through the `ScramUpgrader` trait.

use super::*;
use crate::directory_store::{AccountStore, DynamicAccount, NoopScramUpgrader, ScramUpgrader};
use crate::smtp::auth::tests::hash;
use crate::smtp::scram::{SCRAM_ITERATIONS, ScramCredentials, ScramStored};
use crate::test_fixtures as fixtures;

#[test]
fn fresh_salt_uses_the_current_iteration_count() {
	// The constant matches OWASP 2023 PBKDF2-HMAC-SHA256, so a brand-new
	// account immediately pays the same cost the password hash does. A
	// regression that lowers it would let a reader of accounts.toml attack
	// the verifier cheaper than the argon2 hash.
	let stored = ScramStored::with_fresh_salt(fixtures::password()).expect("csprng");
	assert_eq!(stored.iterations, SCRAM_ITERATIONS);
	assert_eq!(stored.iterations, 600_000);
}

#[test]
fn server_first_carries_the_stored_iteration_count() {
	// Whatever the constant says, the value the protocol exchanges is the
	// stored one (RFC 5802 `i=`). A regression that swaps to the live
	// constant would break clients the moment the constant is raised.
	let salt = vec![0u8; 16];
	let stored_key = [0u8; 32];
	let server_key = [0u8; 32];
	let stored = ScramStored::from_credentials(&ScramCredentials {
		salt: salt.clone(),
		iterations: 4096,
		stored_key,
		server_key,
	});
	let credentials = stored.to_credentials().expect("valid base64");
	let mut server = crate::smtp::scram::ScramServer::new(fixtures::nonce());
	let (_, server_first) = server
		.first("n,,n=alice,r=CN", &credentials)
		.expect("first");
	assert!(
		server_first.contains(",i=4096"),
		"server-first must echo the stored iteration count, got {server_first}"
	);
}

#[test]
fn stored_low_iteration_verifier_still_authenticates() {
	// Pre-fix accounts keep their 4096 verifier until the upgrade path
	// rewrites them; the directory has to honour the stored value on the
	// first exchange or every upgraded account fails SCRAM until its
	// first PLAIN login.
	let password = fixtures::password();
	let credentials = ScramCredentials::derive(password, fixtures::salt(), 4096);
	let stored = ScramStored::from_credentials(&credentials);
	let directory = Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([("alice".to_string(), hash(password))])
	.with_scram([("alice".to_string(), stored)]);
	let recovered = directory.scram_credentials("alice").expect("stored creds");
	assert_eq!(recovered.iterations, 4096);
}

/// Test double that captures every upgrade request.
#[derive(Debug, Clone, Default)]
struct RecordingUpgrader {
	last: std::sync::Arc<std::sync::Mutex<Option<String>>>,
	calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ScramUpgrader for RecordingUpgrader {
	fn upgrade(&self, account: &str, _password: &str) {
		*self.last.lock().expect("upgrade record") = Some(account.to_string());
		self.calls
			.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
	}
}

fn open_store(
	account: DynamicAccount,
	upgrader: std::sync::Arc<dyn ScramUpgrader>,
) -> AccountStore {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("store open");
	store.add(account).expect("add");
	store.with_scram_upgrader(upgrader)
}

#[test]
fn successful_cleartext_auth_asks_for_a_4096_verifier_rewrite() {
	// A pre-fix account keeps its 4096 verifier until PLAIN/LOGIN succeed.
	// The first successful cleartext login against it hands the password to
	// the upgrader; the rewrite itself is pinned against the real store in
	// `directory_store::scram_upgrade::tests`.
	let password = fixtures::password();
	let low =
		ScramStored::from_credentials(&ScramCredentials::derive(password, fixtures::salt(), 4096));
	let account = DynamicAccount {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: hash(password),
		scram: Some(low.clone()),
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
	};
	let recorder = RecordingUpgrader::default();
	let recorder_arc: std::sync::Arc<dyn ScramUpgrader> = std::sync::Arc::new(recorder.clone());
	let store = open_store(account, recorder_arc.clone());
	let directory = store.handle().current();
	assert_eq!(
		directory
			.scram_credentials("alice")
			.expect("scram")
			.iterations,
		4096,
		"precondition: pre-upgrade verifier is the 4096 row"
	);

	let verified =
		directory.authenticate_with_ip("alice", password, None, crate::config::Protocol::Api);
	assert_eq!(verified.as_deref(), Some("alice"));

	let upgraded = recorder.last.lock().expect("upgrade record").clone();
	assert_eq!(upgraded.as_deref(), Some("alice"));
	assert_eq!(recorder.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn successful_cleartext_auth_does_not_rewrite_an_upgraded_verifier() {
	// Once a verifier is already at the current iteration count, the
	// upgrade is a no-op. The salt must not churn either, so the cost is
	// one extra map lookup on every PLAIN/LOGIN, no PBKDF2 cost.
	let password = fixtures::password();
	let fresh = ScramStored::with_fresh_salt(password).expect("csprng");
	let account = DynamicAccount {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: hash(password),
		scram: Some(fresh.clone()),
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
	};
	let recorder = RecordingUpgrader::default();
	let recorder_arc: std::sync::Arc<dyn ScramUpgrader> = std::sync::Arc::new(recorder.clone());
	let store = open_store(account, recorder_arc);
	let directory = store.handle().current();

	directory
		.authenticate_with_ip("alice", password, None, crate::config::Protocol::Api)
		.expect("auth");

	assert_eq!(
		recorder.calls.load(std::sync::atomic::Ordering::Relaxed),
		0,
		"verifier already at the current count; no rewrite"
	);
}

#[test]
fn failed_cleartext_auth_does_not_rewrite_the_verifier() {
	// The upgrade follows a successful argon2id verify; a wrong password
	// must leave the verifier untouched. Without this guard an attacker
	// who knows the SCRAM salt could cycle the verifier on every failed
	// attempt, paying the SCRAM cost themselves and denying service to
	// the legitimate user.
	let password = fixtures::password();
	let low =
		ScramStored::from_credentials(&ScramCredentials::derive(password, fixtures::salt(), 4096));
	let account = DynamicAccount {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: hash(password),
		scram: Some(low.clone()),
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
	};
	let recorder = RecordingUpgrader::default();
	let recorder_arc: std::sync::Arc<dyn ScramUpgrader> = std::sync::Arc::new(recorder.clone());
	let store = open_store(account, recorder_arc);
	let directory = store.handle().current();

	let verified = directory.authenticate_with_ip(
		"alice",
		fixtures::wrong_password(),
		None,
		crate::config::Protocol::Api,
	);
	assert!(verified.is_none(), "wrong password must fail");
	assert_eq!(
		recorder.calls.load(std::sync::atomic::Ordering::Relaxed),
		0,
		"a failed PLAIN must not rewrite the verifier"
	);
}

#[test]
fn static_accounts_are_not_rewritten_by_the_upgrade() {
	// The directory's SCRAM map only carries dynamic accounts; a static
	// account under mail.toml has no `scram_upgrader`-reachable row, so
	// the upgrade is a no-op regardless of the iteration constant.
	let recorder = RecordingUpgrader::default();
	let recorder_arc: std::sync::Arc<dyn ScramUpgrader> = std::sync::Arc::new(recorder.clone());
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![crate::config::Account {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: Some(hash(fixtures::password())),
			quota_bytes: None,
			allowed_protocols: None,
			catch_all: Vec::new(),
			forward: Vec::new(),
			forward_keep_local: false,
		}],
	)
	.expect("store open")
	.with_scram_upgrader(recorder_arc);
	let directory = store.handle().current();

	directory
		.authenticate_with_ip(
			"alice",
			fixtures::password(),
			None,
			crate::config::Protocol::Api,
		)
		.expect("auth");

	assert_eq!(
		recorder.calls.load(std::sync::atomic::Ordering::Relaxed),
		0,
		"static accounts have no dynamic row to rewrite"
	);
}

#[test]
fn noop_upgrader_does_not_panic() {
	// The default upgrader is a no-op; without it the directory still
	// answers correctly to a successful PLAIN, even though nothing is
	// persisted. Keeps the CLI path (which never wires a real upgrader)
	// safe.
	let password = fixtures::password();
	let account = DynamicAccount {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: hash(password),
		scram: Some(ScramStored::with_fresh_salt(password).expect("csprng")),
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
	};
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("store open");
	store.add(account).expect("add");
	let upgrader: std::sync::Arc<dyn ScramUpgrader> = std::sync::Arc::new(NoopScramUpgrader);
	let store = store.with_scram_upgrader(upgrader);
	let directory = store.handle().current();

	assert_eq!(
		directory
			.authenticate_with_ip("alice", password, None, crate::config::Protocol::Api,)
			.as_deref(),
		Some("alice")
	);
}
