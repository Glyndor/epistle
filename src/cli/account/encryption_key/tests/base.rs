//! `account show` names the key that protects an account's new mail.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::*;

fn key(dir: &Path, name: &str) -> PathBuf {
	let path = dir.join(name);
	std::fs::write(
		&path,
		crate::storage::generate_key_base64().expect("csprng"),
	)
	.expect("key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path
}

/// A config with a server key, tenant acme with its own key, and three
/// accounts: one inside acme, one half outside it, one in no tenant.
fn setup(dir: &Path, encrypt: bool) -> (PathBuf, AccountStore) {
	let text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {data:?}\ndomains = [\"acme.test\", \"plain.test\"]\n\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@acme.test\"]\n\n\
		 [[accounts]]\nname = \"frank\"\naddresses = [\"frank@acme.test\", \"frank@plain.test\"]\n\n\
		 [[accounts]]\nname = \"bob\"\naddresses = [\"bob@plain.test\"]\n\n\
		 [storage]\nencrypt_at_rest = {encrypt}\ntenant_keys = {encrypt}\nencryption_key_file = {server:?}\n\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"acme.test\"]\nencryption_key_file = {acme:?}\n",
		data = dir.display().to_string(),
		server = key(dir, "server.key").display().to_string(),
		acme = key(dir, "acme.key").display().to_string(),
	);
	let path = dir.join("mail.toml");
	std::fs::write(&path, text).expect("config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let config = Config::load(&path).expect("load");
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("store");
	(path, store)
}

#[test]
fn each_account_names_its_key_and_why() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (path, store) = setup(dir.path(), true);
	let alice = describe(&path, &store, "alice");
	assert!(
		alice.starts_with("the key of tenant \"acme\", key "),
		"alice resolves to the acme key"
	);
	let frank = describe(&path, &store, "frank");
	assert!(
		frank.starts_with("the server key, key "),
		"frank stays on the server key"
	);
	assert!(
		frank.contains("outside tenant \"acme\""),
		"frank's line says why"
	);
	let bob = describe(&path, &store, "bob");
	assert!(
		bob.starts_with("the server key, key "),
		"bob stays on the server key"
	);
	assert_ne!(alice.split(';').next(), bob.split(';').next());
}

#[test]
fn without_encryption_nothing_protects_new_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (path, store) = setup(dir.path(), false);
	assert_eq!(
		describe(&path, &store, "alice"),
		"none (encrypt_at_rest is off)"
	);
}
