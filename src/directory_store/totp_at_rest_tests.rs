//! The TOTP secret in `accounts.toml` under at-rest encryption: encrypted
//! when a key is configured, legacy cleartext still read and sealed on the
//! next write, and unchanged when encryption is off.

use crate::config::Protocol;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::{fixture_password, hash};
use crate::storage::MessageCrypto;
use crate::test_fixtures as fixtures;

fn open(dir: &std::path::Path, crypto: &MessageCrypto) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
	.with_crypto(crypto.clone())
}

fn add_alice(store: &AccountStore, totp_secret: Option<String>) {
	store
		.add(DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: hash(fixture_password()),
			scram: None,
			totp_secret,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			..DynamicAccount::default()
		})
		.expect("add alice");
}

fn accounts_file(dir: &std::path::Path) -> String {
	std::fs::read_to_string(dir.join("accounts.toml")).expect("read accounts.toml")
}

/// Whether `alice` authenticates with her password followed by the current
/// code for `secret`, through a store freshly opened from disk.
fn totp_login_works(dir: &std::path::Path, crypto: &MessageCrypto, secret: &str) -> bool {
	let bytes = crate::totp::decode_base32_secret(secret).expect("base32");
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	let code = crate::totp::totp(&bytes, now);
	let directory = open(dir, crypto).handle().current();
	let with_code = format!("{}{code:06}", fixture_password());
	let accepted = directory.authenticate("alice", &with_code, Protocol::Imap);
	// Without the code the login must fail, or TOTP is not being enforced.
	let without_code = directory.authenticate("alice", fixture_password(), Protocol::Imap);
	accepted.as_deref() == Some("alice") && without_code.is_none()
}

fn fresh_secret() -> String {
	crate::totp::encode_base32(&fixtures::bytes::<20>())
}

#[test]
fn with_a_key_the_file_never_holds_the_base32_secret() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&fixtures::bytes::<32>());
	let store = open(dir.path(), &crypto);
	add_alice(&store, None);
	let secret = fresh_secret();
	store.set_totp("alice", Some(secret.clone())).expect("set");

	let file = accounts_file(dir.path());
	assert!(
		!file.contains(&secret),
		"accounts.toml must not contain the TOTP secret in cleartext"
	);
	assert!(
		file.contains("totp_secret = \"enc:v1:"),
		"the stored secret must be the self-describing encrypted form"
	);
	assert!(
		totp_login_works(dir.path(), &crypto, &secret),
		"TOTP must still verify against the decrypted secret"
	);
}

#[test]
fn a_legacy_cleartext_secret_still_verifies_and_is_sealed_on_the_next_write() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = fresh_secret();
	// Written by a version without TOTP encryption.
	add_alice(
		&open(dir.path(), &MessageCrypto::disabled()),
		Some(secret.clone()),
	);
	assert!(accounts_file(dir.path()).contains(&secret), "precondition");

	let crypto = MessageCrypto::for_test(&fixtures::bytes::<32>());
	assert!(
		totp_login_works(dir.path(), &crypto, &secret),
		"a cleartext secret must keep working once encryption is on"
	);

	// Any write of the account rewrites it under the key.
	open(dir.path(), &crypto)
		.set_quota_bytes("alice", Some(1 << 20))
		.expect("write alice");
	let file = accounts_file(dir.path());
	assert!(
		!file.contains(&secret),
		"the next write must replace the cleartext secret"
	);
	assert!(file.contains("totp_secret = \"enc:v1:"));
	assert!(totp_login_works(dir.path(), &crypto, &secret));
}

#[test]
fn without_a_key_the_secret_is_stored_as_before() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::disabled();
	let store = open(dir.path(), &crypto);
	add_alice(&store, None);
	let secret = fresh_secret();
	store.set_totp("alice", Some(secret.clone())).expect("set");

	assert!(
		accounts_file(dir.path()).contains(&format!("totp_secret = \"{secret}\"")),
		"without at-rest encryption the secret keeps its cleartext form"
	);
	assert!(totp_login_works(dir.path(), &crypto, &secret));
}

#[test]
fn a_sealed_secret_without_the_key_disables_the_login_instead_of_bypassing_totp() {
	// A store opened without the key (a misconfigured restart) must not
	// treat an undecryptable secret as "no TOTP": the account would then
	// log in with the password alone.
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(&fixtures::bytes::<32>());
	let store = open(dir.path(), &crypto);
	add_alice(&store, None);
	store.set_totp("alice", Some(fresh_secret())).expect("set");

	let directory = open(dir.path(), &MessageCrypto::disabled())
		.handle()
		.current();
	assert_eq!(
		directory.authenticate("alice", fixture_password(), Protocol::Imap),
		None,
		"an unreadable TOTP secret must fail closed"
	);
}
