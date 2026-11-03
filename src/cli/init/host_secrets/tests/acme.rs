//! The ACME account key across a switch of layout: copied, never lost, and
//! removed from data_dir only when the copy in `secrets/` is the same key.

use std::fs;
use std::path::Path;

use crate::cli::init::host_secrets::acme::{place, retire_data_dir_copy, split_dirs};

fn data_dir(root: &Path) -> std::path::PathBuf {
	let data_dir = root.join("data");
	fs::create_dir_all(&data_dir).expect("data_dir");
	data_dir
}

/// An account key as `mail` writes it, under data_dir.
fn renewing_key(data_dir: &Path) -> Vec<u8> {
	crate::acme::renew::load_or_create_account_key(data_dir).expect("account key");
	fs::read(crate::acme::renew::account_key_path(data_dir)).expect("read key")
}

#[test]
fn turning_certs_on_copies_the_key_the_authority_knows() {
	let root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_dir(root.path());
	let key = renewing_key(&data_dir);

	let lines = place(&data_dir, true).expect("place");

	assert!(
		fs::read(super::acme_account_key(&data_dir)).expect("copied") == key,
		"the same key"
	);
	assert!(
		fs::read(crate::acme::renew::account_key_path(&data_dir)).expect("still there") == key,
		"the copy the old layout reads stays until the new one is verified"
	);
	assert!(
		lines.iter().any(|line| line.contains("copied")),
		"{lines:?}"
	);
	for dir in split_dirs(&data_dir) {
		assert!(dir.is_dir(), "{} for the bind mounts", dir.display());
	}
}

#[test]
fn turning_certs_on_without_any_key_creates_one_the_container_can_read() {
	let root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_dir(root.path());

	let lines = place(&data_dir, true).expect("place");

	let created = super::acme_account_key(&data_dir);
	crate::acme::renew::load_or_create_account_key_at(&created).expect("a usable key");
	assert!(
		lines.iter().any(|line| line.contains("created")),
		"{lines:?}"
	);
	use std::os::unix::fs::PermissionsExt;
	let mode = fs::metadata(&created)
		.expect("metadata")
		.permissions()
		.mode();
	assert_eq!(mode & 0o077, 0, "{mode:o}");
}

#[test]
fn two_different_keys_are_never_reconciled() {
	let root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_dir(root.path());
	let key = renewing_key(&data_dir);
	let other = super::acme_account_key(&data_dir);
	fs::create_dir_all(other.parent().expect("parent")).expect("secrets");
	crate::acme::renew::load_or_create_account_key_at(&other).expect("another key");

	let error = place(&data_dir, true).expect_err("two keys");
	assert!(error.contains("different ACME account keys"), "{error}");
	assert!(
		fs::read(crate::acme::renew::account_key_path(&data_dir)).expect("kept") == key,
		"the same key"
	);
	let error = retire_data_dir_copy(&data_dir).expect_err("two keys");
	assert!(error.contains("different ACME account keys"), "{error}");
	assert!(crate::acme::renew::account_key_path(&data_dir).exists());
}

#[test]
fn the_data_dir_copy_is_removed_only_once_secrets_holds_the_same_key() {
	let root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_dir(root.path());
	let key = renewing_key(&data_dir);

	let error = retire_data_dir_copy(&data_dir).expect_err("the only copy");
	assert!(error.contains("the only ACME account key"), "{error}");
	assert!(crate::acme::renew::account_key_path(&data_dir).exists());

	place(&data_dir, true).expect("place");
	let line = retire_data_dir_copy(&data_dir).expect("retire");
	assert!(line.is_some_and(|line| line.contains("removed")));
	assert!(!crate::acme::renew::account_key_path(&data_dir).exists());
	assert!(
		fs::read(super::acme_account_key(&data_dir)).expect("kept") == key,
		"the same key"
	);
	assert_eq!(retire_data_dir_copy(&data_dir).expect("again"), None);
}

#[test]
fn turning_certs_off_puts_the_key_back_where_mail_reads_it() {
	let root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_dir(root.path());
	let key = renewing_key(&data_dir);
	place(&data_dir, true).expect("on");
	retire_data_dir_copy(&data_dir).expect("retire");

	let lines = place(&data_dir, false).expect("off");

	assert!(
		fs::read(crate::acme::renew::account_key_path(&data_dir)).expect("back") == key,
		"the same key"
	);
	assert!(
		fs::read(super::acme_account_key(&data_dir)).expect("kept") == key,
		"the secrets copy is kept: it is not mounted in mail"
	);
	assert!(
		lines.iter().any(|line| line.contains("copied")),
		"{lines:?}"
	);
	assert!(place(&data_dir, false).expect("again").is_empty());
}

#[test]
fn a_key_path_that_is_not_a_file_is_refused() {
	let root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_dir(root.path());
	let path = crate::acme::renew::account_key_path(&data_dir);
	fs::create_dir_all(&path).expect("a directory where the key goes");
	let error = place(&data_dir, true).expect_err("not a file");
	assert!(error.contains("not a regular file"), "{error}");
}

#[test]
fn a_bound_directory_that_is_a_symlink_is_refused_before_anything_is_placed() {
	for index in 0..2 {
		let root = tempfile::tempdir().expect("tempdir");
		let data_dir = data_dir(root.path());
		// A directory mail writes, and a link to it where certs binds from.
		let elsewhere = data_dir.join("spool");
		fs::create_dir_all(&elsewhere).expect("spool");
		let dir = split_dirs(&data_dir)[index].clone();
		std::os::unix::fs::symlink(&elsewhere, &dir).expect("link");

		let error = place(&data_dir, true).expect_err("a link");

		assert!(error.contains("is not a directory"), "{error}");
		assert!(
			fs::symlink_metadata(&dir)
				.expect("still there")
				.file_type()
				.is_symlink(),
			"left for the operator"
		);
		assert!(
			!super::acme_account_key(&data_dir).exists(),
			"no key placed for a layout that cannot run"
		);
	}
}
