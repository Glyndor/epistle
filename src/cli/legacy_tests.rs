//! Every flat command still parses, is hidden from `--help`, and stands
//! for exactly the resource action its documented replacement parses to.

use clap::{CommandFactory, Parser};

use super::{Legacy, Resource};
use crate::cli::{Cli, Command};

/// Each flat command line and the resource command line it is an alias of.
const PAIRS: &[(&[&str], &[&str])] = &[
	(&["accounts"], &["account", "list"]),
	(
		&[
			"account-add",
			"--name",
			"bob",
			"--address",
			"bob@example.org",
		],
		&["account", "add", "bob", "--address", "bob@example.org"],
	),
	(
		&[
			"account-remove",
			"--name",
			"bob",
			"--queue",
			"drain",
			"--yes",
		],
		&["account", "remove", "bob", "--queue", "drain", "--yes"],
	),
	(
		&[
			"app-password-create",
			"--account",
			"bob",
			"--label",
			"phone",
			"--expires-at",
			"99",
			"--ip-cidr",
			"203.0.113.0/24",
		],
		&[
			"app-password",
			"create",
			"bob",
			"phone",
			"--expires-at",
			"99",
			"--ip-cidr",
			"203.0.113.0/24",
		],
	),
	(&["app-passwords"], &["app-password", "list"]),
	(
		&[
			"app-password-revoke",
			"--account",
			"bob",
			"--label",
			"phone",
			"-y",
		],
		&["app-password", "revoke", "bob", "phone", "-y"],
	),
	(
		&[
			"api-key-create",
			"--label",
			"ci",
			"--scope",
			"read",
			"--scope",
			"send",
			"--account",
			"bob",
		],
		&[
			"api-key",
			"create",
			"ci",
			"--scope",
			"read",
			"--scope",
			"send",
			"--account",
			"bob",
		],
	),
	(&["api-keys"], &["api-key", "list"]),
	(
		&["api-key-revoke", "--label", "ci", "--yes"],
		&["api-key", "revoke", "ci", "--yes"],
	),
];

fn parse(args: &[&str]) -> Command {
	let argv = std::iter::once("epistle")
		.chain(args.iter().copied())
		.chain(["--config", "/srv/mail.toml"]);
	Cli::try_parse_from(argv)
		.unwrap_or_else(|error| panic!("{args:?} does not parse: {error}"))
		.command
}

/// The resource action a parsed resource command line carries.
fn resource_of(command: Command) -> (std::path::PathBuf, Resource) {
	match command {
		Command::Account { config, action, .. } => (config, Resource::Account(action)),
		Command::AppPassword { config, action } => (config, Resource::AppPassword(action)),
		Command::ApiKey { config, action } => (config, Resource::ApiKey(action)),
		other => panic!("not a resource command: {other:?}"),
	}
}

#[test]
fn every_flat_command_is_its_resource_action() {
	for (flat, resource) in PAIRS {
		let Command::Legacy(legacy) = parse(flat) else {
			panic!("{flat:?} did not parse as a flat command");
		};
		let (flat_config, flat_action) = legacy.into_resource();
		let (config, action) = resource_of(parse(resource));
		assert_eq!(flat_config, config, "{flat:?}");
		assert_eq!(
			format!("{flat_action:?}"),
			format!("{action:?}"),
			"{flat:?} is not {resource:?}"
		);
	}
}

#[test]
fn every_flat_command_is_hidden_from_help() {
	let help = Cli::command().render_help().to_string();
	for (flat, _) in PAIRS {
		let name = flat[0];
		assert!(
			!help
				.lines()
				.any(|line| line.trim_start().starts_with(&format!("{name} "))),
			"{name} is listed in --help"
		);
	}
	let legacy_names: Vec<String> =
		<Legacy as clap::Subcommand>::augment_subcommands(clap::Command::new("probe"))
			.get_subcommands()
			.map(|sub| sub.get_name().to_string())
			.collect();
	let flats: Vec<&str> = PAIRS.iter().map(|(flat, _)| flat[0]).collect();
	assert_eq!(legacy_names, flats, "a flat command has no alias test");
}
