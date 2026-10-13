//! Tests for `api-key create --account` (account-bound management keys).
//!
//! Lives in a sibling so `api_keys_tests.rs` and friends stay under
//! the per-file line budget. The store already supports
//! `key.account`; these tests pin the CLI surface (parsing, validation,
//! and the on-disk form `api_keys.toml` ends up with).

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::directory_store::{AccountStore, DynamicAccount};

const DOMAIN: &str = "example.org";

fn write_config(data_dir: &std::path::Path) -> tempfile::NamedTempFile {
	let cfg = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"{DOMAIN}\"]\n",
		data_dir
	);
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	use std::io::Write as _;
	file.write_all(cfg.as_bytes()).expect("write");
	file
}

fn seed_bob(data_dir: &std::path::Path) {
	let store = AccountStore::open(
		data_dir,
		vec![DOMAIN.to_string()],
		Default::default(),
		Vec::new(),
	)
	.expect("open");
	store
		.add(DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: crate::smtp::auth::tests::hash(
				crate::smtp::auth::tests::fixture_password(),
			),
			..DynamicAccount::default()
		})
		.expect("add bob");
}

#[test]
fn api_key_create_with_account_flag_parses() {
	let cli = Cli::try_parse_from([
		"epistle",
		"api-key",
		"--config",
		"/etc/mail.toml",
		"create",
		"ci",
		"--scope",
		"read",
		"--account",
		"bob",
	])
	.expect("parses");
	match cli.command {
		Command::ApiKey { action, .. } => match action {
			crate::cli::api_keys::ApiKeyCli::Create {
				label,
				account,
				scopes,
				..
			} => {
				assert_eq!(label, "ci");
				assert_eq!(account.as_deref(), Some("bob"));
				assert_eq!(scopes, vec!["read".to_string()]);
			}
			other => panic!("expected Create, got {other:?}"),
		},
		other => panic!("expected Command::ApiKey, got {other:?}"),
	}
}

#[test]
fn api_key_resource_create_runs_end_to_end_with_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(dir.path());
	seed_bob(dir.path());
	let cli = Cli::try_parse_from([
		"epistle",
		"api-key",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"create",
		"ci",
		"--scope",
		"read",
		"--account",
		"bob",
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::SUCCESS);
	let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("api_keys.toml");
	assert!(
		text.contains("account = \"bob\""),
		"key was not bound to bob on disk: {text}"
	);
	assert!(text.contains("[keys]") || text.contains("[[keys]]"));
}

#[test]
fn api_key_create_refuses_unknown_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(dir.path());
	seed_bob(dir.path());
	let cli = Cli::try_parse_from([
		"epistle",
		"api-key",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"create",
		"ci",
		"--scope",
		"read",
		"--account",
		"unseen-person",
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::from(2));
}

#[test]
fn api_key_account_bound_rejects_scim_scope() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(dir.path());
	seed_bob(dir.path());
	let cli = Cli::try_parse_from([
		"epistle",
		"api-key",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"create",
		"ci",
		"--scope",
		"scim",
		"--account",
		"bob",
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::from(2));
	// And the file was not written.
	let path = dir.path().join("api_keys.toml");
	let exists = path.exists();
	assert!(!exists, "api_keys.toml should not exist for a refused key");
}

#[test]
fn flat_api_key_create_with_account_still_parses() {
	let cli = Cli::try_parse_from([
		"epistle",
		"api-key-create",
		"--config",
		"/etc/mail.toml",
		"--label",
		"ci",
		"--scope",
		"read",
		"--account",
		"bob",
	])
	.expect("flat form parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::ApiKeyCreate { .. })
	));
}
