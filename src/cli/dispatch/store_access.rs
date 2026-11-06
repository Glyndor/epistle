//! Keep an offline operation inside one shared store lease, before it loads
//! crypto. Serve and tenant-key migration own their longer-lived guards.

use super::{Command, Config};
use crate::cli::{archive, legacy::Legacy};
use crate::storage::lock::FileLock;

pub(super) fn guard(command: &Command) -> Result<Option<FileLock>, String> {
	let path = match command {
		Command::Import { config, .. }
		| Command::Export { config, .. }
		| Command::Backup { config, .. }
		| Command::Restore { config, .. }
		| Command::Verify { config, .. }
		| Command::Account { config, .. }
		| Command::AppPassword { config, .. }
		| Command::ApiKey { config, .. }
		| Command::Domain { config, .. }
		| Command::Alias { config, .. }
		| Command::Suppression { config, .. }
		| Command::Masked { config, .. }
		| Command::Queue { config, .. }
		| Command::Warmup { config, .. }
		| Command::Learning { config, .. }
		| Command::ReportAbuse { config, .. } => config,
		Command::Storage {
			config,
			action: crate::cli::storage::blobs::StorageCli::Blobs { .. },
			..
		} => config,
		Command::Migrate(args) => &args.config,
		Command::Archive { action, .. } => match action {
			archive::Subcommand::List { config, .. }
			| archive::Subcommand::Restore { config, .. }
			| archive::Subcommand::Purge { config, .. } => config,
		},
		Command::Legacy(action) => match action {
			Legacy::Accounts { config, .. }
			| Legacy::AccountAdd { config, .. }
			| Legacy::AccountRemove { config, .. }
			| Legacy::AppPasswordCreate { config, .. }
			| Legacy::AppPasswords { config, .. }
			| Legacy::AppPasswordRevoke { config, .. }
			| Legacy::ApiKeyCreate { config, .. }
			| Legacy::ApiKeys { config, .. }
			| Legacy::ApiKeyRevoke { config, .. } => config,
		},
		// Every other command is named here, so a new `Command` variant does not compile
		// until someone decides whether it needs the lease. Do not turn this back into a
		// wildcard.
		//
		// Hold their own longer lived guard: `serve`, and `storage tenant-keys` (migration).
		Command::Serve { .. } | Command::Storage { .. } => return Ok(None),
		// Never open the mail store: keys, documents printed from the configuration, DNS and
		// TLS checks, status, the stack, and the commands that only read or write
		// configuration or operational state outside the encrypted mail files.
		Command::MtaStsServe { .. }
		| Command::ConfigCheck { .. }
		| Command::DkimKeygen { .. }
		| Command::StorageKeygen { .. }
		| Command::OauthKeygen { .. }
		| Command::VerifyDns { .. }
		| Command::DnsRecords { .. }
		| Command::Mobileconfig { .. }
		| Command::SrvRecords { .. }
		| Command::Autoconfig { .. }
		| Command::Autodiscover { .. }
		| Command::Delivery { .. }
		| Command::Evidence { .. }
		| Command::Ban { .. }
		| Command::TokenHash { .. }
		| Command::Reports { .. }
		| Command::Local { .. }
		| Command::Init { .. }
		| Command::Limits { .. }
		| Command::Dns { .. }
		| Command::Webhook { .. }
		| Command::Alert { .. }
		| Command::Relay { .. }
		| Command::Service { .. }
		| Command::Status { .. }
		| Command::Check { .. }
		| Command::Antispam { .. }
		| Command::Attachments { .. }
		| Command::Stack { .. }
		| Command::Db { .. }
		| Command::Dkim { .. }
		| Command::Tls { .. }
		| Command::Probe { .. }
		| Command::Completions { .. }
		| Command::MoveSubids { .. }
		| Command::Manpages { .. } => return Ok(None),
	};
	let config = Config::load(path).map_err(|error| error.to_string())?;
	FileLock::store_shared(&config.data_dir)
		.map(Some)
		.map_err(|error| error.to_string())
}
