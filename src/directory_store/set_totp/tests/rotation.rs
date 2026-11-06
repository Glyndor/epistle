//! A TOTP secret sealed under a server key that was then retired is
//! resealed under the current key, so the retired key can go.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::config::Storage;
use crate::directory_store::{AccountStore, DynamicAccount};

fn key(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
	let path = dir.join(name);
	std::fs::write(
		&path,
		crate::storage::generate_key_base64().expect("csprng"),
	)
	.expect("key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path
}

fn crypto(current: &std::path::Path, retired: &[&std::path::Path]) -> MessageCrypto {
	let storage = Storage {
		encrypt_at_rest: true,
		encryption_key_file: Some(current.to_path_buf()),
		retired_key_files: retired.iter().map(|path| path.to_path_buf()).collect(),
		..Storage::default()
	};
	MessageCrypto::from_config(Some(&storage)).expect("crypto")
}

fn store(dir: &std::path::Path, crypto: &MessageCrypto) -> AccountStore {
	AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store")
	.with_crypto(crypto.clone())
}

fn stored_secret(dir: &std::path::Path, crypto: &MessageCrypto) -> String {
	store(dir, crypto)
		.dynamic("alice")
		.and_then(|account| account.totp_secret)
		.expect("a stored secret")
}

#[test]
fn a_secret_under_a_retired_key_is_resealed_under_the_current_one() {
	let data = tempfile::tempdir().expect("data");
	let keys = tempfile::tempdir().expect("keys");
	let old = key(keys.path(), "old.key");
	let new = key(keys.path(), "new.key");
	// Base32 letters drawn at run time: no secret sits in the source.
	let secret: String = crate::storage::generate_key_base64()
		.expect("csprng")
		.chars()
		.filter(char::is_ascii_alphabetic)
		.map(|letter| letter.to_ascii_uppercase())
		.take(16)
		.collect();

	let before = store(data.path(), &crypto(&old, &[]));
	before
		.add(DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			totp_secret: Some(secret.clone()),
			..DynamicAccount::default()
		})
		.expect("add alice");

	let rotated = crypto(&new, &[&old]);
	assert_eq!(
		open(&rotated, &stored_secret(data.path(), &rotated)),
		secret
	);
	assert_eq!(
		store(data.path(), &rotated).reseal_totp().expect("reseal"),
		1
	);
	assert_eq!(
		store(data.path(), &rotated).reseal_totp().expect("again"),
		0,
		"nothing is left under the retired key"
	);

	// The retired key is gone from the configuration: the secret still opens.
	let current_only = crypto(&new, &[]);
	assert_eq!(
		open(&current_only, &stored_secret(data.path(), &current_only)),
		secret
	);
}
