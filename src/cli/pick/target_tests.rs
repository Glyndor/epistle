//! Which argument a usage error is missing, read from clap's own error and
//! the command line, and whether it is one an operator can pick from a list.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{CommandFactory, Parser};

use super::*;
use crate::cli::Cli;

/// What `argv` is missing, as the picker sees it.
fn wanted(argv: &[&str]) -> Option<Want> {
	let args: Vec<OsString> = argv.iter().map(OsString::from).collect();
	let error = Cli::try_parse_from(&args).expect_err("an argument is missing");
	want(&Cli::command(), &error, &args)
}

#[test]
fn a_missing_account_name_is_picked_and_the_config_comes_from_the_command_line() {
	let want =
		wanted(&["epistle", "account", "show", "--config", "/srv/mail.toml"]).expect("pickable");
	assert_eq!(want.kind, Kind::Account);
	assert_eq!(want.insert, Insert::Positional);
	assert_eq!(want.config, PathBuf::from("/srv/mail.toml"));
}

#[test]
fn the_config_defaults_to_the_packaged_path() {
	let want = wanted(&["epistle", "account", "disable"]).expect("pickable");
	assert_eq!(want.config, PathBuf::from(crate::cli::DEFAULT_CONFIG));
}

#[test]
fn a_name_for_something_new_is_never_picked() {
	assert!(wanted(&["epistle", "account", "add", "--address", "a@example.org"]).is_none());
	assert!(wanted(&["epistle", "alias", "add"]).is_none());
	assert!(wanted(&["epistle", "domain", "add"]).is_none());
	assert!(wanted(&["epistle", "api-key", "create"]).is_none());
}

#[test]
fn an_option_that_names_the_account_is_inserted_with_its_flag() {
	let want = wanted(&["epistle", "export", "--config", "/srv/mail.toml"]).expect("pickable");
	assert_eq!(want.kind, Kind::Account);
	assert_eq!(want.insert, Insert::Option("--account".to_string()));
}

#[test]
fn aliases_domains_and_key_labels_are_picked() {
	let alias = wanted(&["epistle", "alias", "--config", "/m.toml", "remove"]).expect("alias");
	assert_eq!(alias.kind, Kind::Alias);
	assert_eq!(alias.config, PathBuf::from("/m.toml"));
	assert_eq!(
		wanted(&["epistle", "alias", "member", "add"]).map(|w| w.kind),
		Some(Kind::Alias)
	);
	assert_eq!(
		wanted(&["epistle", "domain", "remove", "--yes"]).map(|w| w.kind),
		Some(Kind::Domain)
	);
	assert_eq!(
		wanted(&["epistle", "api-key", "rotate"]).map(|w| w.kind),
		Some(Kind::ApiKey)
	);
	assert_eq!(
		wanted(&["epistle", "api-key", "revoke"]).map(|w| w.kind),
		Some(Kind::ApiKey)
	);
}

#[test]
fn an_app_password_label_is_picked_from_the_account_already_given() {
	let want = wanted(&["epistle", "app-password", "revoke", "alice"]).expect("pickable");
	assert_eq!(want.kind, Kind::AppPassword("alice".to_string()));
	let first = wanted(&["epistle", "app-password", "revoke"]).expect("pickable");
	assert_eq!(first.kind, Kind::Account, "the account comes first");
}

#[test]
fn a_missing_subcommand_or_an_unknown_flag_is_not_a_pick() {
	let args: Vec<OsString> = ["epistle", "account", "show", "--bogus"]
		.iter()
		.map(OsString::from)
		.collect();
	let error = Cli::try_parse_from(&args).expect_err("unknown flag");
	assert!(want(&Cli::command(), &error, &args).is_none());
}

#[test]
fn the_value_lands_where_clap_reads_it() {
	let args: Vec<OsString> = ["epistle", "account", "show", "--json"]
		.iter()
		.map(OsString::from)
		.collect();
	let with = insert(&args, &Insert::Positional, "alice");
	assert!(Cli::try_parse_from(&with).is_ok(), "{with:?}");
	let args: Vec<OsString> = ["epistle", "export"].iter().map(OsString::from).collect();
	let with = insert(&args, &Insert::Option("--account".into()), "alice");
	let cli = Cli::try_parse_from(&with).expect("parses");
	assert!(matches!(
		cli.command,
		crate::cli::Command::Export { ref account, .. } if account == "alice"
	));
}

#[test]
fn a_value_after_a_double_dash_still_parses() {
	let args: Vec<OsString> = ["epistle", "account", "show", "--"]
		.iter()
		.map(OsString::from)
		.collect();
	let error = Cli::try_parse_from(&args).expect_err("missing");
	assert!(want(&Cli::command(), &error, &args).is_some());
	let with = insert(&args, &Insert::Positional, "alice");
	assert!(Cli::try_parse_from(&with).is_ok(), "{with:?}");
	let _ = Cli::parse_from(["epistle", "account", "show", "alice"]);
}
