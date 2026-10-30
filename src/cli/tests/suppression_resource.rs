//! Tests for the `epistle suppression list|add|remove` resource form.
//!
//! Lives in a sibling so `suppression_tests.rs` stays under the
//! per-file code-line budget. Verifies the resource parser picks up
//! each new variant, the legacy `--remove` form still parses to the
//! same hidden alias, and the resource list/add/remove actions reach
//! the same `SuppressionList` mutators the flat commands reach.

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};
use crate::queue::SuppressionList;

fn empty_dir() -> tempfile::TempDir {
	tempfile::tempdir().expect("tempdir")
}

#[test]
fn suppression_list_resource_parses() {
	let cli = Cli::try_parse_from(["epistle", "suppression", "list"]).expect("list parses");
	match cli.command {
		Command::Suppression { action, .. } => {
			assert!(matches!(
				action,
				Some(crate::cli::suppression::SuppressionCli::List { .. })
			));
		}
		other => panic!("expected Command::Suppression, got {other:?}"),
	}
}

#[test]
fn suppression_add_resource_parses() {
	let cli = Cli::try_parse_from(["epistle", "suppression", "add", "bob@example.net"])
		.expect("add parses");
	match cli.command {
		Command::Suppression { action, .. } => match action {
			Some(crate::cli::suppression::SuppressionCli::Add {
				address, account, ..
			}) => {
				assert_eq!(address, "bob@example.net");
				assert!(account.is_none());
			}
			other => panic!("expected Add, got {other:?}"),
		},
		other => panic!("expected Command::Suppression, got {other:?}"),
	}
}

#[test]
fn suppression_remove_resource_parses_with_account() {
	let cli = Cli::try_parse_from([
		"epistle",
		"suppression",
		"remove",
		"bob@example.net",
		"--account",
		"alice@example.org",
	])
	.expect("remove parses");
	match cli.command {
		Command::Suppression { action, .. } => match action {
			Some(crate::cli::suppression::SuppressionCli::Remove {
				address, account, ..
			}) => {
				assert_eq!(address, "bob@example.net");
				assert_eq!(account.as_deref(), Some("alice@example.org"));
			}
			other => panic!("expected Remove, got {other:?}"),
		},
		other => panic!("expected Command::Suppression, got {other:?}"),
	}
}

#[test]
fn flat_suppression_with_remove_still_parses() {
	let cli = Cli::try_parse_from(["epistle", "suppression", "--remove", "bob@example.net"])
		.expect("flat --remove parses");
	assert!(matches!(cli.command, Command::Suppression { .. }));
}

#[test]
fn suppression_add_then_remove_round_trip() {
	let dir = empty_dir();
	let cfg = {
		let mut f = tempfile::NamedTempFile::new().expect("file");
		use std::io::Write as _;
		writeln!(
			f,
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.net\"]\n",
			dir.path()
		)
		.expect("write");
		f
	};
	// add bob globally
	let add = Cli::try_parse_from([
		"epistle",
		"suppression",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"add",
		"bob@example.net",
	])
	.expect("parses");
	assert_eq!(add.run(), ExitCode::SUCCESS);
	// confirm via the store
	assert!(
		SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);

	// remove via the resource form
	let rm = Cli::try_parse_from([
		"epistle",
		"suppression",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"remove",
		"bob@example.net",
	])
	.expect("parses");
	assert_eq!(rm.run(), ExitCode::SUCCESS);
	assert!(
		!SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);
}

#[test]
fn suppression_legacy_remove_still_works() {
	let dir = empty_dir();
	let cfg = {
		let mut f = tempfile::NamedTempFile::new().expect("file");
		use std::io::Write as _;
		writeln!(
			f,
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.net\"]\n",
			dir.path()
		)
		.expect("write");
		f
	};
	// Add via resource form, remove via legacy `--remove` form.
	let add = Cli::try_parse_from([
		"epistle",
		"suppression",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"add",
		"bob@example.net",
	])
	.expect("parses");
	assert_eq!(add.run(), ExitCode::SUCCESS);
	let legacy = Cli::try_parse_from([
		"epistle",
		"suppression",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"--remove",
		"bob@example.net",
	])
	.expect("parses");
	assert_eq!(legacy.run(), ExitCode::SUCCESS);
	assert!(
		!SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);
}

#[test]
fn suppression_resource_list_in_help() {
	let help = Cli::command().render_long_help().to_string();
	assert!(
		help.contains("Manage the outbound suppression list"),
		"resource umbrella missing: {help}"
	);
}

#[test]
fn suppression_help_hides_the_legacy_flags() {
	let mut root = Cli::command();
	let help = root
		.find_subcommand_mut("suppression")
		.expect("suppression subcommand")
		.render_long_help()
		.to_string();
	assert!(!help.contains("--remove"), "legacy --remove shown: {help}");
	assert!(help.contains("list"), "list action missing: {help}");
}

#[test]
fn suppression_list_json_prints_an_array_of_objects() {
	let dir = empty_dir();
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n",
		dir.path()
	))
	.expect("config");
	let list = SuppressionList::open(dir.path()).expect("open");
	list.suppress("bob@example.net");
	list.suppress_for("alice", "carol@example.net");

	let mut out = Vec::new();
	let action = crate::cli::suppression::SuppressionCli::List {
		account: None,
		json: true,
	};
	assert_eq!(
		crate::cli::suppression::run(&config, action, &mut out),
		ExitCode::SUCCESS
	);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	assert_eq!(
		value,
		serde_json::json!([{ "address": "bob@example.net", "account": null, "since": null, "reason": null }])
	);

	let mut out = Vec::new();
	let action = crate::cli::suppression::SuppressionCli::List {
		account: Some("alice".to_string()),
		json: true,
	};
	assert_eq!(
		crate::cli::suppression::run(&config, action, &mut out),
		ExitCode::SUCCESS
	);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	assert_eq!(
		value,
		serde_json::json!([{ "address": "carol@example.net", "account": "alice", "since": null, "reason": null }])
	);
}
