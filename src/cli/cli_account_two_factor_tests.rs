//! Tests for `epistle account 2fa show|disable` and the supporting
//! store mutator.
//!
//! Sibling module so `cli_account_subcommand_tests.rs` stays under the
//! per-file code-line budget. Drives `set_totp` directly (the path
//! the CLI uses for both enrol-style `set` flows and the new disable)
//! and exercises the parser shape end-to-end.

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::directory_store::AccountStore;
use crate::smtp::auth::tests::{fixture_password, hash};

const DOMAIN: &str = "example.org";

fn open_store(data_dir: &std::path::Path) -> AccountStore {
	AccountStore::open(
		data_dir,
		vec![DOMAIN.to_string()],
		Default::default(),
		Vec::new(),
	)
	.expect("open store")
}

fn seed_bob(store: &AccountStore) {
	store
		.add(crate::directory_store::DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: hash(fixture_password()),
			..crate::directory_store::DynamicAccount::default()
		})
		.expect("add bob");
}

#[test]
fn two_factor_resource_parser_maps_to_subcommand() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		"/etc/mail.toml",
		"two-factor",
		"show",
		"bob",
	])
	.expect("account two-factor show parses");
	match cli.command {
		Command::Account { action, .. } => match action {
			crate::cli::account::Subcommand::TwoFactor(args) => match args.action {
				crate::cli::account::TwoFactorSubcommand::Show { name, .. } => {
					assert_eq!(name, "bob");
				}
				other => panic!("expected TwoFactorSubcommand::Show, got {other:?}"),
			},
			other => panic!("expected Subcommand::TwoFactor, got {other:?}"),
		},
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn two_factor_disable_resource_parser_captures_yes() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		"/etc/mail.toml",
		"two-factor",
		"disable",
		"bob",
		"--yes",
	])
	.expect("account two-factor disable parses");
	match cli.command {
		Command::Account { action, .. } => match action {
			crate::cli::account::Subcommand::TwoFactor(args) => match args.action {
				crate::cli::account::TwoFactorSubcommand::Disable { name, yes } => {
					assert_eq!(name, "bob");
					assert!(yes);
				}
				other => panic!("expected TwoFactorSubcommand::Disable, got {other:?}"),
			},
			other => panic!("expected Subcommand::TwoFactor, got {other:?}"),
		},
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn set_totp_then_clear_round_trip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	// Start with no TOTP.
	assert!(store.dynamic_account("bob").unwrap().totp_secret.is_none());
	// Enrol a fake secret.
	store
		.set_totp("bob", Some("JBSWY3DPEHPK3PXP".to_string()))
		.expect("set");
	assert!(store.dynamic_account("bob").unwrap().totp_secret.is_some());
	// Disable clears it back to None.
	store.set_totp("bob", None).expect("clear");
	assert!(store.dynamic_account("bob").unwrap().totp_secret.is_none());
}

#[test]
fn account_run_two_factor_show_dispatches() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg_text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"{DOMAIN}\"]\n",
		dir.path()
	);
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	use std::io::Write as _;
	file.write_all(cfg_text.as_bytes()).expect("write");
	// Seed bob via the store first.
	{
		let store = open_store(dir.path());
		seed_bob(&store);
		store
			.set_totp("bob", Some("JBSWY3DPEHPK3PXP".to_string()))
			.expect("set totp");
	}
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		file.path().to_str().expect("utf8 path"),
		"two-factor",
		"show",
		"bob",
	])
	.expect("account two-factor show parses");
	assert_eq!(cli.run(), ExitCode::SUCCESS);
}

#[test]
fn account_run_two_factor_show_unknown_account_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg_text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"{DOMAIN}\"]\n",
		dir.path()
	);
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	use std::io::Write as _;
	file.write_all(cfg_text.as_bytes()).expect("write");
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		file.path().to_str().expect("utf8 path"),
		"two-factor",
		"show",
		"unknown-account",
	])
	.expect("parses");
	assert_eq!(cli.run(), ExitCode::from(2));
}
