use super::*;
use clap::Parser;

#[test]
fn domain_limits_parse_set_unset_and_delegate() {
	for arguments in [
		vec![
			"epistle",
			"limits",
			"set",
			"quota",
			"--domain",
			"example.org",
			"10G",
		],
		vec![
			"epistle",
			"limits",
			"set",
			"submission-rate",
			"--domain",
			"example.org",
			"50",
		],
		vec![
			"epistle",
			"limits",
			"unset",
			"quota",
			"--domain",
			"example.org",
			"--dry-run",
		],
	] {
		let cli = Cli::try_parse_from(arguments).unwrap();
		assert!(
			cli.command.requires_service_user(),
			"domain limits must delegate to the service user"
		);
	}
}
