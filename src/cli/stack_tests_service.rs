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
