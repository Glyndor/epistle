use super::*;
use clap::Parser;

#[test]
fn limits_commands_delegate_to_the_service_user() {
	for args in [
		vec!["epistle", "limits", "show"],
		vec!["epistle", "limits", "set", "quota", "5G"],
		vec!["epistle", "limits", "unset", "quota"],
	] {
		let cli = Cli::try_parse_from(args);
		assert_eq!(
			cli.as_ref()
				.ok()
				.map(|cli| cli.command.requires_service_user()),
			Some(true),
			"limits administration must delegate to the service user"
		);
	}
}
