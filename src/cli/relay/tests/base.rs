use std::path::PathBuf;

use clap::CommandFactory;

use super::*;
use crate::cli::Cli;
use crate::cli::resource::test_config;

pub(super) const RULES: &str = "
# default route
[[transport]] # catch-all
kind = 'relay'
host = 'smtp.example.net'
port  =  587 # submission
starttls = true
username = 'u' # who
password = 'p-secret'

[[transport]]
domain = 'example.org'
kind = 'fail'
";

pub(super) fn no_restart(_: &Config, _: StackAction) -> ExitCode {
	panic!("a test host has no compose file, so nothing may be restarted")
}

fn capture(args: Vec<&str>) -> (Result<ExitCode, super::resource::ResourceError>, String) {
	let (_dir, file) = test_config(RULES);
	let action = parse(&args);
	let mut out = Vec::new();
	let result = execute_with(
		file.path(),
		action,
		false,
		false,
		&mut std::io::BufReader::new(std::io::empty()),
		&mut out,
		&mut Vec::new(),
		no_restart,
	);
	(result, String::from_utf8(out).unwrap())
}

pub(super) fn parse(args: &[&str]) -> RelayCli {
	let mut full = vec!["epistle", "relay"];
	full.extend_from_slice(args);
	match <Cli as clap::Parser>::try_parse_from(full).unwrap().command {
		crate::cli::Command::Relay { action, .. } => action,
		_ => unreachable!("relay arguments must select the relay command"),
	}
}

#[test]
fn relay_accepts_config_before_or_after_the_action_and_defaults_it() {
	let matches = Cli::command()
		.try_get_matches_from(["epistle", "relay", "list"])
		.unwrap();
	assert_eq!(
		matches
			.subcommand_matches("relay")
			.unwrap()
			.get_one::<PathBuf>("config")
			.unwrap(),
		&PathBuf::from("/etc/epistle/mail.toml")
	);
	for args in [
		["epistle", "relay", "--config", "/tmp/x.toml", "list"],
		["epistle", "relay", "list", "--config", "/tmp/x.toml"],
	] {
		let matches = Cli::command().try_get_matches_from(args).unwrap();
		assert_eq!(
			matches
				.subcommand_matches("relay")
				.unwrap()
				.get_one::<PathBuf>("config")
				.unwrap(),
			&PathBuf::from("/tmp/x.toml")
		);
	}
}

#[test]
fn account_and_domain_selectors_conflict() {
	let error = Cli::command()
		.try_get_matches_from([
			"epistle",
			"relay",
			"show",
			"--account",
			"a",
			"--domain",
			"b.org",
		])
		.unwrap_err();
	assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn list_prints_relay_rules_only_and_never_the_password() {
	let (result, out) = capture(vec!["list"]);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		out, "default\tsmtp.example.net:587\tstarttls=yes\tauth=yes\n",
		"the fail rule is not a relay and must not be listed"
	);
	let (_, json) = capture(vec!["list", "--json"]);
	assert_eq!(
		json,
		"[{\"target\":\"default\",\"account\":null,\"domain\":null,\"host\":\"smtp.example.net\",\"port\":587,\"starttls\":true,\"username\":\"u\",\"password\":\"set\",\"socks_proxy\":null,\"enabled\":true}]\n"
	);
}

#[test]
fn show_prints_the_selected_rule_and_masks_the_password() {
	let (result, out) = capture(vec!["show"]);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		out,
		"target\tdefault\nhost\tsmtp.example.net\nport\t587\nstarttls\ttrue\nusername\tu\npassword\tset\nsocks_proxy\t-\nenabled\tyes\n"
	);
	assert!(
		!out.contains("p-secret"),
		"show must never print the password"
	);
}

#[test]
fn show_reports_a_missing_rule_and_a_non_relay_rule() {
	for (args, label) in [
		(vec!["show", "--account", "alice"], "account alice"),
		(
			vec!["show", "--domain", "example.org"],
			"domain example.org",
		),
	] {
		let (result, out) = capture(args);
		assert_eq!(
			result.unwrap_err().as_ref(),
			format!("no relay is configured for {label}")
		);
		assert!(out.is_empty());
	}
}
