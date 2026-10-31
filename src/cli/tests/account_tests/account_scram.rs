//! `epistle account password` against `[auth] scram`.
//!
//! The CLI opens its own store from the config file, so the flag has to
//! reach that store too: with `scram = false` a password change must drop
//! the account's verifier instead of deriving a new one.

use std::io::Cursor;

use super::*;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::auth::tests::base::{fixture_password, hash};
use crate::smtp::scram::{SCRAM_ITERATIONS, ScramCredentials, ScramStored};

const NAME: &str = "bob";

/// A data dir holding `bob` with a verifier, and a config file pointing at
/// it with the given `[auth]` section appended.
fn harness(auth_section: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	store
		.add(DynamicAccount {
			name: NAME.to_string(),
			addresses: vec![format!("{NAME}@example.org")],
			password_hash: hash(fixture_password()),
			scram: Some(ScramStored::from_credentials(&ScramCredentials::derive(
				fixture_password(),
				crate::test_fixtures::salt(),
				4096,
			))),
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			..DynamicAccount::default()
		})
		.expect("add bob");
	let mut config = tempfile::NamedTempFile::new().expect("config file");
	std::io::Write::write_all(
		&mut config,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\n{auth_section}",
			dir.path()
		)
		.as_bytes(),
	)
	.expect("write config");
	(dir, config)
}

/// Change bob's password through the CLI path and return the verifier
/// left on disk.
fn change_password(dir: &std::path::Path, config: &std::path::Path) -> Option<ScramStored> {
	let store = account::prepare(config, NAME).expect("prepare");
	let new_password = crate::test_fixtures::second_password();
	assert_eq!(
		account::password_with_store(
			&store,
			NAME,
			Cursor::new(format!("{new_password}\n")),
			&mut std::io::sink(),
			false
		),
		ExitCode::SUCCESS
	);
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("reopen")
	.dynamic(NAME)
	.expect("bob")
	.scram
}

#[test]
fn password_change_with_scram_disabled_drops_the_verifier() {
	let (dir, config) = harness("[auth]\nscram = false\n");
	let after = change_password(dir.path(), config.path());
	assert!(
		after.is_none(),
		"with scram = false the CLI password change must leave no verifier"
	);
}

#[test]
fn password_change_with_scram_enabled_derives_a_current_verifier() {
	let (dir, config) = harness("");
	let after = change_password(dir.path(), config.path()).expect("verifier");
	assert_eq!(after.iterations, SCRAM_ITERATIONS);
}
