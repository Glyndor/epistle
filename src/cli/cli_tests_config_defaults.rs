use super::*;
use crate::cli::command_cases::CASES;
use clap::Parser;
use std::path::Path;

fn config_path(command: &Command) -> Option<&Path> {
	match command {
		Command::Serve { config }
		| Command::ConfigCheck { config }
		| Command::Probe { config, .. }
		| Command::Export { config, .. }
		| Command::Import { config, .. }
		| Command::Backup { config }
		| Command::Restore { config, .. }
		| Command::Verify { config }
		| Command::VerifyDns { config }
		| Command::DnsRecords { config }
		| Command::Mobileconfig { config, .. }
		| Command::SrvRecords { config }
		| Command::Autoconfig { config, .. }
		| Command::Autodiscover { config, .. }
		| Command::Suppression { config, .. }
		| Command::ReportAbuse { config }
		| Command::Legacy(crate::cli::legacy::Legacy::Accounts { config })
		| Command::Legacy(crate::cli::legacy::Legacy::AccountAdd { config, .. })
		| Command::Legacy(crate::cli::legacy::Legacy::AccountRemove { config, .. })
		| Command::Account { config, .. }
		| Command::Queue { config, .. }
		| Command::Ban { config, .. } => Some(config),
		Command::Delivery(args) => Some(&args.config),
		| Command::Masked { config, .. }
		| Command::Legacy(crate::cli::legacy::Legacy::AppPasswordCreate { config, .. })
		| Command::Legacy(crate::cli::legacy::Legacy::AppPasswords { config })
		| Command::Legacy(crate::cli::legacy::Legacy::AppPasswordRevoke { config, .. })
		| Command::AppPassword { config, .. }
		| Command::Legacy(crate::cli::legacy::Legacy::ApiKeyCreate { config, .. })
		| Command::Legacy(crate::cli::legacy::Legacy::ApiKeys { config })
		| Command::Legacy(crate::cli::legacy::Legacy::ApiKeyRevoke { config, .. })
		| Command::Reports { config, .. } => Some(config),
		Command::MoveSubids(args) => Some(&args.config),
		Command::Migrate(args) => Some(&args.config),
		Command::Stack { config, .. }
		| Command::Service { config, .. }
		| Command::Limits { config, .. }
		| Command::Status { config, .. }
		| Command::Check { config, .. }
		| Command::Relay { config, .. }
		| Command::Dns { config, .. }
		| Command::Storage { config, .. }
		| Command::Webhook { config, .. }
		| Command::Alert { config, .. }
		| Command::Antispam { config, .. }
		| Command::Alias { config, .. }
		| Command::Domain { config, .. }
		| Command::Dkim { config, .. }
		| Command::Tls { config, .. }
		| Command::ApiKey { config, .. }
		| Command::Db { config, .. } => Some(config),
		Command::Archive { action } => match action {
			archive::Subcommand::List { config, .. }
			| archive::Subcommand::Restore { config, .. }
			| archive::Subcommand::Purge { config, .. } => Some(config),
		},
		Command::MtaStsServe { .. }
		| Command::DkimKeygen { .. }
		| Command::StorageKeygen
		| Command::OauthKeygen { .. }
		| Command::TokenHash
		| Command::Local { .. }
		| Command::Completions { .. }
		| Command::Manpages { .. }
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
