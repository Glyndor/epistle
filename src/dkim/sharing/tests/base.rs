//! The public keys behind the files decide sharing, not their names.

use std::path::{Path, PathBuf};

use super::*;

fn new_key(dir: &Path, name: &str) -> PathBuf {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let path = dir.join(name);
	std::fs::write(&path, pem).expect("key file");
	path
}

fn rsa_key(dir: &Path, name: &str) -> PathBuf {
	let path = dir.join(name);
	let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dkim/test_rsa_key.pem");
	std::fs::copy(source, &path).expect("rsa key file");
	path
}

fn config(dir: &Path, dkim: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['a.example', 'b.example']\n{dkim}"
	))
	.expect("config")
}

fn entry(name: &str, file: &Path) -> String {
	format!("[[dkim.domain]]\nname = '{name}'\nselector = 's1'\nkey_file = {file:?}\n")
}

#[test]
fn keys_that_differ_share_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let default = new_key(dir.path(), "default.pem");
	let a = new_key(dir.path(), "a.pem");
	let config = config(
		dir.path(),
		&format!(
			"[dkim]\nselector = 's1'\nkey_file = {default:?}\n{}",
			entry("a.example", &a)
		),
	);
	assert_eq!(shared_public_keys(&config), Ok(Vec::new()));
}

#[test]
fn a_copy_of_one_key_under_two_names_is_the_same_key() {
	let dir = tempfile::tempdir().expect("dir");
	let default = new_key(dir.path(), "default.pem");
	let a = new_key(dir.path(), "a.pem");
	let b = dir.path().join("b.pem");
	std::fs::copy(&a, &b).expect("copy");
	let config = config(
		dir.path(),
		&format!(
			"[dkim]\nselector = 's1'\nkey_file = {default:?}\n{}{}",
			entry("a.example", &a),
			entry("b.example", &b)
		),
	);
	let found = shared_public_keys(&config).expect("read");
	assert_eq!(found.len(), 1, "{found:?}");
	assert!(
		found[0].contains("[dkim.domain] name = \"a.example\"")
			&& found[0].contains("[dkim.domain] name = \"b.example\"")
			&& found[0].contains("the same ed25519 public key"),
		"{found:?}"
	);
}

#[test]
fn an_entry_that_copies_the_default_key_shares_it() {
	let dir = tempfile::tempdir().expect("dir");
	let default = new_key(dir.path(), "default.pem");
	let copy = dir.path().join("copy.pem");
	std::fs::copy(&default, &copy).expect("copy");
	let config = config(
		dir.path(),
		&format!(
			"[dkim]\nselector = 's1'\nkey_file = {default:?}\n{}",
			entry("a.example", &copy)
		),
	);
	let found = shared_public_keys(&config).expect("read");
	assert_eq!(found.len(), 1, "{found:?}");
	assert!(
		found[0].contains("[dkim] (the key every domain"),
		"{found:?}"
	);
}

#[test]
fn the_rsa_key_is_compared_too_and_never_against_ed25519() {
	let dir = tempfile::tempdir().expect("dir");
	let default = new_key(dir.path(), "default.pem");
	let rsa_default = rsa_key(dir.path(), "rsa-default.pem");
	let a = new_key(dir.path(), "a.pem");
	let rsa_a = rsa_key(dir.path(), "rsa-a.pem");
	let config = config(
		dir.path(),
		&format!(
			"[dkim]\nselector = 's1'\nkey_file = {default:?}\nrsa_selector = 's2'\nrsa_key_file = {rsa_default:?}\n\
			 {}rsa_selector = 's2'\nrsa_key_file = {rsa_a:?}\n",
			entry("a.example", &a)
		),
	);
	let found = shared_public_keys(&config).expect("read");
	assert_eq!(found.len(), 1, "{found:?}");
	assert!(found[0].contains("the same rsa public key"), "{found:?}");
}

#[test]
fn a_key_that_does_not_load_is_left_to_the_signer() {
	let dir = tempfile::tempdir().expect("dir");
	let default = new_key(dir.path(), "default.pem");
	let missing = dir.path().join("missing.pem");
	let config = config(
		dir.path(),
		&format!(
			"[dkim]\nselector = 's1'\nkey_file = {default:?}\n{}",
			entry("a.example", &missing)
		),
	);
	assert_eq!(shared_public_keys(&config), Ok(Vec::new()));
}

#[test]
fn the_key_in_service_after_a_rotation_is_the_one_compared() {
	let dir = tempfile::tempdir().expect("dir");
	let configured = new_key(dir.path(), "default.pem");
	let rotated = new_key(dir.path(), "dkim-ed100.key");
	let a = dir.path().join("a.pem");
	std::fs::copy(&rotated, &a).expect("copy");
	let state = serde_json::json!({
		"selector": "ed100", "key_file": "dkim-ed100.key", "rotated_at": 1, "previous": null
	});
	std::fs::write(dir.path().join("dkim-rotation.json"), state.to_string()).expect("state");
	let config = config(
		dir.path(),
		&format!(
			"[dkim]\nselector = 's1'\nkey_file = {configured:?}\n{}",
			entry("a.example", &a)
		),
	);
	let found = shared_public_keys(&config).expect("read");
	assert_eq!(
		found.len(),
		1,
		"an override equal to the rotated key is shared: {found:?}"
	);
}
