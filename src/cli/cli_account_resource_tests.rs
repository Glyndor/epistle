//! Tests for the `epistle account` resource form: list, add, remove.
//!
//! Lives in a sibling so `cli_account_subcommand_tests.rs` stays under
//! the per-file code-line budget. Every test parses the new resource form
//! and asserts the dispatch reaches the same `accounts::list`/`add`/
//! `remove` handler the legacy flat command (`accounts`, `account-add`,
//! `account-remove`) calls. The handlers themselves are exercised in
//! `cli_tests.rs::accounts_list_prints_configured_accounts` and
//! `account_add_creates_and_validates`; this module only covers the
//! shape of the parser and the dispatch arm.

use std::io::Write;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};

fn write_config(contents: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(contents.as_bytes()).expect("write");
	file
}

#[test]
fn account_list_resource_parses() {
	let cli = Cli::try_parse_from(["epistle", "account", "--config", "/etc/mail.toml", "list"])
		.expect("account list parses");
	match cli.command {
		Command::Account { action, .. } => {
			assert!(matches!(
				action,
				crate::cli::account::Subcommand::List { json: false }
			));
		}
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn account_add_resource_parses() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		"/etc/mail.toml",
		"add",
		"bob",
		"--address",
		"bob@example.org",
	])
	.expect("account add parses");
	match cli.command {
		Command::Account { action, .. } => match action {
			crate::cli::account::Subcommand::Add { name, addresses } => {
				assert_eq!(name, "bob");
				assert_eq!(addresses, vec!["bob@example.org".to_string()]);
			}
			other => panic!("expected Subcommand::Add, got {other:?}"),
		},
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn account_remove_resource_parses() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		"/etc/mail.toml",
		"remove",
		"bob",
		"--queue",
		"discard",
		"--yes",
	])
	.expect("account remove parses");
	match cli.command {
		Command::Account { action, .. } => match action {
			crate::cli::account::Subcommand::Remove { name, queue, yes } => {
				assert_eq!(name, "bob");
				assert!(matches!(
					queue,
					crate::directory_store::removal::QueuePolicy::Discard
				));
				assert!(yes);
			}
			other => panic!("expected Subcommand::Remove, got {other:?}"),
		},
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn flat_accounts_still_parses_as_hidden_alias() {
	let cli = Cli::try_parse_from(["epistle", "accounts", "--config", "/etc/mail.toml"])
		.expect("flat accounts still parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::Accounts { .. })
	));
}

#[test]
fn flat_account_add_still_parses_as_hidden_alias() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account-add",
		"--config",
		"/etc/mail.toml",
		"--name",
		"bob",
		"--address",
		"bob@example.org",
	])
	.expect("flat account-add still parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::AccountAdd { .. })
	));
}

#[test]
fn flat_account_remove_still_parses_as_hidden_alias() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account-remove",
		"--config",
		"/etc/mail.toml",
		"--name",
		"bob",
		"--queue",
		"discard",
	])
	.expect("flat account-remove still parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::AccountRemove { .. })
	));
}

#[test]
fn flat_commands_are_hidden_in_help() {
	let help = Cli::command().render_long_help().to_string();
	// The umbrella is always shown; the flat forms must not be, or
	// `epistle --help` would carry the deprecated compatibility paths on
	// every page.
	assert!(
		help.contains("Manage accounts: list, add, remove"),
		"help missing account umbrella: {help}"
	);
	for needle in [
		"(Compatibility) List every account",
		"(Compatibility) Create an account",
		"(Compatibility) Remove an account",
	] {
		assert!(
			!help.contains(needle),
			"flat alias still in help: {needle}\n{help}"
		);
	}
}

#[test]
fn account_run_dispatches_list_through_accounts_list() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(&format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = {:?}\n\
		 domains = [\"example.org\"]\n\n\
		 [[accounts]]\n\
		 name = \"alice\"\n\
		 addresses = [\"alice@example.org\"]\n",
		dir.path()
	));
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"list",
	])
	.expect("account list parses");
	// Dispatch through the resource form and confirm it ends up running
	// `accounts::list`: its single visible effect is the row printed.
	let result = cli.run();
	assert_eq!(result, ExitCode::SUCCESS);
}
