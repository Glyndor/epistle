use crate::cli::{Cli, Command};
use clap::Parser;
use std::path::Path;

#[test]
fn stack_defaults_to_the_packaged_config_path() {
	let cli = Cli::try_parse_from(["epistle", "stack", "up"]).unwrap();
	let Command::Stack { config, .. } = cli.command else {
		panic!("expected stack command");
	};
	assert_eq!(
		Some(config.as_path()),
		Some(Path::new("/etc/epistle/mail.toml")),
		"stack must default to the configuration written by packaged init"
	);
}

#[test]
fn no_restart_is_accepted_around_the_subcommand_and_apply_is_a_stack_verb() {
	for args in [
		["epistle", "--no-restart", "stack", "apply"],
		["epistle", "stack", "apply", "--no-restart"],
	] {
		let cli = Cli::try_parse_from(args).unwrap();
		assert!(cli.no_restart, "{args:?}");
		assert!(matches!(
			cli.command,
			Command::Stack {
				action: crate::cli::stack::StackCli::Apply,
				..
			}
		));
	}
	let cli = Cli::try_parse_from(["epistle", "stack", "apply"]).unwrap();
	assert!(!cli.no_restart, "the default keeps restarting");
}
