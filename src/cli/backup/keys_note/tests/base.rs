//! What `backup` and `restore` say about the keys kept outside data_dir.

use super::*;

fn text(bytes: Vec<u8>) -> String {
	String::from_utf8(bytes).unwrap()
}

#[test]
fn a_backup_names_the_keys_it_does_not_carry() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	let secrets = root.path().join("secrets");
	std::fs::create_dir_all(&secrets).unwrap();
	std::fs::write(secrets.join("storage.key"), b"k").unwrap();
	std::fs::write(secrets.join("oauth_signing.key"), b"k").unwrap();
	let mut out = Vec::new();
	after_backup(&data_dir, &mut out);
	let out = text(out);
	assert!(out.contains("not in this archive"), "{out}");
	assert!(
		out.contains(secrets.join("storage.key").to_str().unwrap()),
		"{out}"
	);
	assert!(
		out.contains(secrets.join("oauth_signing.key").to_str().unwrap()),
		"{out}"
	);
	assert!(
		out.contains("unreadable"),
		"the consequence is named: {out}"
	);
}

#[test]
fn a_backup_without_those_keys_says_nothing_about_them() {
	let root = tempfile::tempdir().unwrap();
	let mut out = Vec::new();
	after_backup(&root.path().join("data"), &mut out);
	assert!(out.is_empty());
}

#[test]
fn a_restore_says_where_the_keys_have_to_be() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	let entries = vec![("data/accounts.toml".to_string(), 0o600, Vec::new())];
	let mut out = Vec::new();
	after_restore(&data_dir, &entries, &mut out);
	let out = text(out);
	let storage = root.path().join("secrets/storage.key");
	assert!(out.contains(storage.to_str().unwrap()), "{out}");
	assert!(out.contains("before"), "{out}");
}

#[test]
fn a_restore_of_an_older_archive_says_stack_update_moves_the_keys() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	let entries = vec![("data/keys/storage.key".to_string(), 0o600, b"k".to_vec())];
	let mut out = Vec::new();
	after_restore(&data_dir, &entries, &mut out);
	let out = text(out);
	assert!(out.contains("epistle stack update"), "{out}");
	assert!(
		out.contains(data_dir.join("keys/storage.key").to_str().unwrap()),
		"{out}"
	);
}
