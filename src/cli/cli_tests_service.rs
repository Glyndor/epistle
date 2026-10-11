use super::*;
use clap::Parser;

#[test]
fn service_commands_parse_and_delegate_with_packaged_config() {
	for action in [
		vec!["list"],
		vec!["list", "--json"],
		vec!["enable", "imap"],
		vec!["disable", "imaps"],
	] {
		let mut args = vec!["epistle", "service"];
		args.extend(action);
		let parsed = Cli::try_parse_from(args);
		assert!(
			parsed.is_ok(),
			"service subcommands must be accepted by the CLI"
		);
		let cli = parsed.unwrap();
		assert!(
			cli.command.requires_service_user(),
			"service commands must delegate to the service account"
		);
	}
}

#[test]
fn service_commands_require_delegation() {
	for action in [
		vec!["list"],
		vec!["enable", "imap"],
		vec!["disable", "imap"],
	] {
		let mut args = vec!["epistle", "service"];
		args.extend(action);
		let parsed = Cli::try_parse_from(args);
		assert_eq!(
			parsed
				.as_ref()
				.ok()
				.map(|cli| cli.command.requires_service_user()),
			Some(true),
			"service commands must delegate to the service account"
		);
	}
}
