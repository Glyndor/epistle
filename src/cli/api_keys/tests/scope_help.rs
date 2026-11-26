//! The help of every `--scope` option names every scope the parser takes.

use crate::api::api_keys::Scope;
use clap::CommandFactory;

const NAMES: [&str; 9] = [
	"manage:read",
	"manage:write",
	"mail:read",
	"mail:write",
	"send",
	"scim",
	"alias",
	"ban",
	"health",
];

/// What `--help` says under `--scope` for the command at `path`.
fn scope_help(path: &[&str]) -> String {
	let mut command = crate::cli::Cli::command();
	for name in path {
		command = command
			.find_subcommand(name)
			.unwrap_or_else(|| panic!("no command {name}"))
			.clone();
	}
	let scope = command
		.get_arguments()
		.find(|argument| argument.get_long() == Some("scope"))
		.expect("a --scope option");
	scope
		.get_long_help()
		.or_else(|| scope.get_help())
		.expect("help text")
		.to_string()
}

#[test]
fn every_scope_option_names_every_scope() {
	for path in [
		&["api-key", "create"][..],
		&["api-key", "set"][..],
		&["api-key-create"][..],
	] {
		let help = scope_help(path);
		for name in NAMES {
			assert!(name.parse::<Scope>().is_ok(), "{name} is a scope");
			assert!(
				help.contains(&format!("`{name}`")),
				"{path:?} does not name `{name}`: {help}"
			);
		}
	}
}
