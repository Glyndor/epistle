//! End-to-end tests for the SCRAM verifier upgrade through the store that
//! `serve` builds ([`super::super::AccountStore::into_shared`]): the
//! rewrite has to land in `accounts.toml`, not only in a test double.

use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::{digest, hmac, pbkdf2};

use crate::config::Protocol;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::hash;
use crate::smtp::scram::{SCRAM_ITERATIONS, ScramCredentials, ScramServer, ScramStored};
use crate::test_fixtures as fixtures;

const LEGACY_ITERATIONS: u32 = 4096;

fn legacy_verifier() -> ScramStored {
	ScramStored::from_credentials(&ScramCredentials::derive(
		fixtures::password(),
		fixtures::salt(),
		LEGACY_ITERATIONS,
	))
}

/// A store on disk holding `alice` with a 4096-iteration verifier.
fn store_with_legacy_alice(dir: &std::path::Path) -> AccountStore {
	let store = AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("store open");
	store
		.add(DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: hash(fixtures::password()),
			scram: Some(legacy_verifier()),
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
		})
		.expect("add");
	store
}

/// The verifier as persisted, read back through a fresh store on the same
/// directory so the assertion sees `accounts.toml`, not memory.
fn persisted_verifier(dir: &std::path::Path) -> ScramStored {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("reopen")
	.dynamic("alice")
	.expect("alice")
	.scram
	.expect("verifier")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
	let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message);
	tag.as_ref().try_into().expect("32 bytes")
}

/// Run a full SCRAM-SHA-256 exchange as a client knowing `password` and
/// return the server-first message plus whether the server accepted.
fn scram_exchange(credentials: &ScramCredentials, password: &str) -> (String, bool) {
	let mut server = ScramServer::new(fixtures::nonce());
	let (_, server_first) = server
		.first("n,,n=alice,r=clientnonce", credentials)
		.expect("server-first");
	let salt = BASE64
		.decode(
			server_first
				.split(",s=")
				.nth(1)
				.and_then(|r| r.split(',').next())
				.expect("s="),
		)
		.expect("salt");
	let iterations: u32 = server_first
		.rsplit(",i=")
		.next()
		.and_then(|i| i.parse().ok())
		.expect("i=");
	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(iterations).expect("non-zero"),
		&salt,
		password.as_bytes(),
		&mut salted,
	);
	let client_key = hmac_sha256(&salted, b"Client Key");
	let stored_key = digest::digest(&digest::SHA256, &client_key);
	let nonce = server_first
		.strip_prefix("r=")
		.and_then(|r| r.split(',').next())
		.expect("r=");
	let without_proof = format!("c=biws,r={nonce}");
	let auth_message = format!("n=alice,r=clientnonce,{server_first},{without_proof}");
	let signature = hmac_sha256(stored_key.as_ref(), auth_message.as_bytes());
	let proof: Vec<u8> = (0..32).map(|i| client_key[i] ^ signature[i]).collect();
	let client_final = format!("{without_proof},p={}", BASE64.encode(&proof));
	let accepted = server.finish(&client_final, credentials).is_ok();
	(server_first, accepted)
}

#[test]
fn a_stored_4096_verifier_still_authenticates_with_its_own_count() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_legacy_alice(dir.path()).into_shared();
	let credentials = store
		.handle()
		.current()
		.scram_credentials("alice")
		.expect("credentials");
	let (server_first, accepted) = scram_exchange(&credentials, fixtures::password());
	assert!(
		server_first.ends_with(",i=4096"),
		"server-first must announce the stored count: {server_first}"
	);
	assert!(accepted, "the legacy verifier must still authenticate");
}

#[test]
fn a_successful_plain_login_rewrites_a_4096_verifier_on_disk() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_legacy_alice(dir.path()).into_shared();
	let authenticated = store.handle().current().authenticate_with_ip(
		"alice",
		fixtures::password(),
		None,
		Protocol::Imap,
	);
	assert_eq!(authenticated.as_deref(), Some("alice"));

	let persisted = persisted_verifier(dir.path());
	assert_eq!(
		persisted.iterations, SCRAM_ITERATIONS,
		"the persisted verifier must carry the current iteration count"
	);
	assert_ne!(
		persisted.salt,
		legacy_verifier().salt,
		"the rewritten verifier must use a fresh salt"
	);
	// The live directory serves the new verifier, and it still matches the
	// password the account logged in with.
	let credentials = store
		.handle()
		.current()
		.scram_credentials("alice")
		.expect("credentials");
	let (server_first, accepted) = scram_exchange(&credentials, fixtures::password());
	assert!(
		server_first.ends_with(",i=600000"),
		"server-first after the rewrite: {server_first}"
	);
	assert!(accepted, "the rewritten verifier must authenticate");
}

#[test]
fn a_failed_plain_login_leaves_the_verifier_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_legacy_alice(dir.path()).into_shared();
	let authenticated = store.handle().current().authenticate_with_ip(
		"alice",
		fixtures::wrong_password(),
		None,
		Protocol::Imap,
	);
	assert_eq!(authenticated, None);

	let persisted = persisted_verifier(dir.path());
	assert_eq!(persisted.iterations, LEGACY_ITERATIONS);
	assert_eq!(persisted.salt, legacy_verifier().salt);
}

#[test]
fn with_scram_disabled_a_plain_login_does_not_rewrite_the_verifier() {
	// With `[auth] scram = false` no verifier is derived: the login must not
	// pay 600000 PBKDF2 rounds to refresh one nobody can use.
	let dir = tempfile::tempdir().expect("tempdir");
	let store = store_with_legacy_alice(dir.path())
		.with_scram_enabled(false)
		.into_shared();
	let authenticated = store.handle().current().authenticate_with_ip(
		"alice",
		fixtures::password(),
		None,
		Protocol::Imap,
	);
	assert_eq!(authenticated.as_deref(), Some("alice"));

	let persisted = persisted_verifier(dir.path());
	assert_eq!(persisted.iterations, LEGACY_ITERATIONS);
	assert_eq!(persisted.salt, legacy_verifier().salt);
}
