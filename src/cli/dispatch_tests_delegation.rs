use super::*;
use crate::cli::command_cases::CASES;
use clap::{CommandFactory, Parser};
use std::collections::BTreeSet;

#[test]
fn every_command_variant_has_an_explicit_delegation_decision() {
	let declared: BTreeSet<_> = Cli::command()
		.get_subcommands()
		.map(|command| command.get_name().to_owned())
		.collect();
	let tested: BTreeSet<_> = CASES.iter().map(|(args, _)| args[0].to_owned()).collect();
	assert_eq!(
		declared, tested,
		"every Command variant must have a delegation test case"
	);
	for &(args, expected) in CASES {
		let mut argv = vec!["epistle"];
		argv.extend(args);
		if (expected && args[0] != "init") || args[0] == "serve" {
			argv.extend(["--config", "/tmp/mail.toml"]);
		}
		let cli = Cli::try_parse_from(argv).expect("delegation test arguments must parse");
		assert_eq!(
			cli.command.requires_service_user(),
			expected,
			"command {} must use its explicit service-account delegation decision",
			args.join(" ")
		);
	}
}

#[test]
fn help_and_version_exit_before_dispatch() {
	for (args, kind) in [
		(
			vec!["epistle", "--help"],
			clap::error::ErrorKind::DisplayHelp,
		),
		(
			vec!["epistle", "--version"],
			clap::error::ErrorKind::DisplayVersion,
		),
		(
			vec!["epistle", "accounts", "--help"],
			clap::error::ErrorKind::DisplayHelp,
		),
	] {
		assert_eq!(Cli::try_parse_from(args).unwrap_err().kind(), kind);
	}
}
