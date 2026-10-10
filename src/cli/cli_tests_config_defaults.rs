use super::*;
use crate::cli::command_cases::CASES;
use clap::Parser;
use std::path::Path;

fn config_path(command: &Command) -> Option<&Path> {
	match command {
		Command::Serve { config }
		| Command::ConfigCheck { config }
		| Command::Export { config, .. }
		| Command::Import { config, .. }
		| Command::Backup { config }
		| Command::Verify { config }
		| Command::VerifyDns { config }
		| Command::DnsRecords { config }
		| Command::Mobileconfig { config, .. }
		| Command::SrvRecords { config }
		| Command::Autoconfig { config, .. }
		| Command::Autodiscover { config, .. }
		| Command::Suppression { config, .. }
		| Command::ReportAbuse { config }
		| Command::Accounts { config }
		| Command::AccountAdd { config, .. }
		| Command::AccountRemove { config, .. }
		| Command::Queue { config }
		| Command::AppPasswordCreate { config, .. }
		| Command::AppPasswords { config }
		| Command::AppPasswordRevoke { config, .. }
		| Command::ApiKeyCreate { config, .. }
		| Command::ApiKeys { config }
		| Command::ApiKeyRevoke { config, .. }
		| Command::Reports { config, .. } => Some(config),
		Command::Stack { config, .. } => Some(config),
		Command::Archive { action } => match action {
			archive::Subcommand::List { config, .. }
			| archive::Subcommand::Restore { config, .. }
			| archive::Subcommand::Purge { config, .. } => Some(config),
		},
		Command::MtaStsServe { .. }
		| Command::DkimKeygen { .. }
		| Command::StorageKeygen
		| Command::OauthKeygen
		| Command::TokenHash
		| Command::Local { .. }
		| Command::Init { .. } => None,
	}
}

#[test]
fn every_config_command_defaults_to_the_packaged_path_and_accepts_overrides() {
	for &(args, delegated) in CASES {
		if (!delegated && args[0] != "serve") || args[0] == "init" {
			continue;
		}
		let mut argv = vec!["epistle"];
		argv.extend(args);
		let default = Cli::try_parse_from(&argv);
		assert_eq!(
			default
				.as_ref()
				.ok()
				.and_then(|cli| config_path(&cli.command)),
			Some(Path::new("/etc/epistle/mail.toml")),
			"every config command must default to the packaged path: {}",
			args.join(" ")
		);
		argv.extend(["--config", "/tmp/custom.toml"]);
		let explicit = Cli::try_parse_from(argv).unwrap();
		assert_eq!(
			config_path(&explicit.command),
			Some(Path::new("/tmp/custom.toml")),
			"explicit config must override the packaged default"
		);
	}
}
