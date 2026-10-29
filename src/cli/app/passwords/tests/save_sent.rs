//! Tests for the `save_sent` override on `epistle app-password create`.

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::{AppPassword, AppPasswordStore, DynamicAccount};

use crate::cli::app::passwords::tests::*;

fn seed_dynamic_account(dir: &std::path::Path) {
	let store = crate::directory_store::AccountStore::open(
		dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		vec![],
	)
	.expect("open store");
	let alice = DynamicAccount {
		name: "alice".to_string(),
		addresses: vec!["alice@example.org".to_string()],
		password_hash: "$argon2id$secret".to_string(),
		scram: None,
		totp_secret: None,
		disabled: false,
		quota_bytes: None,
		allowed_protocols: None,
		forward: Vec::new(),
		catch_all: Vec::new(),
		display_name: None,
		save_sent: None,
	};
	store.add(alice).expect("add alice");
}

fn write_test_config(dir: &std::path::Path) -> tempfile::NamedTempFile {
	let file = tempfile::NamedTempFile::new().expect("tempfile");
	std::fs::write(
		file.path(),
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
			dir
		),
	)
	.expect("write");
	file
}

#[test]
fn create_with_save_sent_off_persists_the_override() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed_dynamic_account(dir.path());
	let cfg_file = write_test_config(dir.path());
	let cfg = Config::load(cfg_file.path()).expect("load");
	let mut out = Vec::new();
	assert_eq!(
		create(
			&cfg,
			"alice",
			"phone",
			None,
			None,
			Some("off".into()),
			None,
			false,
			&mut out
		),
		ExitCode::SUCCESS
	);
	let store = AppPasswordStore::open(dir.path()).expect("open");
	let entry: &AppPassword = &store.for_account("alice")[0];
	assert_eq!(entry.save_sent, Some(false));
}

#[test]
fn create_with_save_sent_on_persists_the_override() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed_dynamic_account(dir.path());
	let cfg_file = write_test_config(dir.path());
	let cfg = Config::load(cfg_file.path()).expect("load");
	let mut out = Vec::new();
	assert_eq!(
		create(
			&cfg,
			"alice",
			"phone",
			None,
			None,
			Some("on".into()),
			None,
			false,
			&mut out
		),
		ExitCode::SUCCESS
	);
	let store = AppPasswordStore::open(dir.path()).expect("open");
	let entry: &AppPassword = &store.for_account("alice")[0];
	assert_eq!(entry.save_sent, Some(true));
}

#[test]
fn create_without_save_sent_leaves_the_field_unset() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed_dynamic_account(dir.path());
	let cfg_file = write_test_config(dir.path());
	let cfg = Config::load(cfg_file.path()).expect("load");
	let mut out = Vec::new();
	assert_eq!(
		create(
			&cfg, "alice", "phone", None, None, None, None, false, &mut out
		),
		ExitCode::SUCCESS
	);
	let store = AppPasswordStore::open(dir.path()).expect("open");
	let entry: &AppPassword = &store.for_account("alice")[0];
	assert_eq!(entry.save_sent, None);
}

#[test]
fn create_with_a_garbled_save_sent_value_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed_dynamic_account(dir.path());
	let cfg_file = write_test_config(dir.path());
	let cfg = Config::load(cfg_file.path()).expect("load");
	let mut out = Vec::new();
	assert_eq!(
		create(
			&cfg,
			"alice",
			"phone",
			None,
			None,
			Some("maybe".into()),
			None,
			false,
			&mut out,
		),
		ExitCode::FAILURE,
		"a typo on --save-sent is refused without writing the credential"
	);
	let store = AppPasswordStore::open(dir.path()).expect("open");
	assert!(
		store.for_account("alice").is_empty(),
		"the failed create left nothing on disk"
	);
}
