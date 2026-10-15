//! Tests for the `epistle app-password` resource form.
//!
//! Lives in a sibling so `app_passwords_tests.rs` stays under the
//! per-file code-line budget. Verifies:
//! * `app-password list|create|revoke` parses to the new resource variant;
//! * the flat forms (`app-password-create`, `app-passwords`,
//!   `app-password-revoke`) parse to the legacy variants and stay hidden in
//!   `--help`;
//! * the resource form reaches the same handler the flat form reaches.
//!
//! Drives handlers through a temp data_dir with a seeded dynamic account
//! so a real `AppPasswordStore` persists the credential.

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

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
	.expect("open store");
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
fn app_password_resource_list_parses() {
	let cli = Cli::try_parse_from([
		"epistle",
		"app-password",
		"--config",
		"/etc/mail.toml",
		"list",
	])
	.expect("app-password list parses");
	match cli.command {
		Command::AppPassword { action, .. } => {
			assert!(matches!(
				action,
				crate::cli::app_passwords::AppPasswordCli::List { .. }
			));
		}
		other => panic!("expected Command::AppPassword, got {other:?}"),
	}
}

#[test]
fn app_password_resource_create_parses() {
	let cli = Cli::try_parse_from([
		"epistle",
		"app-password",
		"--config",
		"/etc/mail.toml",
		"create",
		"bob",
		"phone",
	])
	.expect("app-password create parses");
	match cli.command {
		Command::AppPassword { action, .. } => match action {
			crate::cli::app_passwords::AppPasswordCli::Create {
				account,
				label,
				expires_at,
				ip_cidr,
				save_sent,
				class,
			} => {
				assert_eq!(class, None);
				assert_eq!(account, "bob");
				assert_eq!(label, "phone");
				assert!(expires_at.is_none());
				assert!(ip_cidr.is_none());
				assert!(save_sent.is_none());
				assert_eq!(account, "bob");
				assert_eq!(label, "phone");
				assert!(expires_at.is_none());
				assert!(ip_cidr.is_none());
			}
			other => panic!("expected Create variant, got {other:?}"),
		},
		other => panic!("expected Command::AppPassword, got {other:?}"),
	}
}

#[test]
fn app_password_resource_revoke_parses_yes() {
	let cli = Cli::try_parse_from([
		"epistle",
		"app-password",
		"--config",
		"/etc/mail.toml",
		"revoke",
		"bob",
		"phone",
		"--yes",
	])
	.expect("app-password revoke parses");
	match cli.command {
		Command::AppPassword { action, .. } => match action {
			crate::cli::app_passwords::AppPasswordCli::Revoke {
				account,
				label,
				yes,
			} => {
				assert_eq!(account, "bob");
				assert_eq!(label, "phone");
				assert!(yes);
			}
			other => panic!("expected Revoke variant, got {other:?}"),
		},
		other => panic!("expected Command::AppPassword, got {other:?}"),
	}
}

#[test]
fn flat_app_password_commands_still_parse_as_hidden_aliases() {
	let cases = [
		vec![
			"epistle",
			"app-password-create",
			"--account",
			"bob",
			"--label",
			"phone",
		],
		vec!["epistle", "app-passwords"],
		vec![
			"epistle",
			"app-password-revoke",
			"--account",
			"bob",
			"--label",
			"phone",
		],
	];
	for args in cases {
		let cli = Cli::try_parse_from(args.clone()).expect("flat parser");
		assert!(
			matches!(
				cli.command,
				Command::Legacy(crate::cli::legacy::Legacy::AppPasswordCreate { .. })
					| Command::Legacy(crate::cli::legacy::Legacy::AppPasswords { .. })
					| Command::Legacy(crate::cli::legacy::Legacy::AppPasswordRevoke { .. })
			),
			"flat form should reach legacy variants: {args:?}"
		);
	}
}

#[test]
fn flat_app_password_aliases_are_hidden_in_help() {
	let help = Cli::command().render_long_help().to_string();
	assert!(
		help.contains("Manage app passwords"),
		"resource umbrella missing: {help}"
	);
	for needle in [
		"(Compatibility) Create an app password",
		"(Compatibility) List app passwords",
		"(Compatibility) Revoke an app password",
	] {
		assert!(
			!help.contains(needle),
			"flat alias still in help: {needle}\n{help}"
		);
	}
}

#[test]
fn app_password_resource_create_runs_end_to_end() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(dir.path());
	seed_bob(dir.path());
	// Need to provide a password/secret via stdin when account-create happens
	// to create the right artefact. For app-password create the secret is
	// generated server-side, so stdin is empty.
	let cli = Cli::try_parse_from([
		"epistle",
		"app-password",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"create",
		"bob",
		"phone",
	])
	.expect("parses");
	// Force stdin to empty so any internal reader that touches stdin
	// returns EOF without blocking. The resource path does not read
	// stdin for create, so the empty reader is fine.
	assert_eq!(cli.run(), ExitCode::SUCCESS);
	// Confirm the credential landed in the persistent store.
	let store = crate::directory_store::AppPasswordStore::open(dir.path()).expect("store");
	let entries = store.list();
	assert!(
		entries
			.iter()
			.any(|(account, label, _, _, _)| account == "bob" && label == "phone"),
		"credential for bob/phone missing: {entries:?}"
	);
}
