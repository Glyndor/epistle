//! Which commands run as the service account.
//!
//! Run as root, a stateful command re-executes itself as the service account
//! before touching anything, so files it writes keep the owner the server
//! expects. The match is exhaustive: a new command must be classified here.

use super::Command;

impl Command {
	pub(super) fn requires_service_user(&self) -> bool {
		// Explicit arms keep new stateful commands from silently running as root.
		match self {
			// Rollback replaces /usr/bin/epistle as root and runs its
			// database half as the account itself.
			Command::Stack {
				action: super::stack::StackCli::Rollback { .. },
				..
			} => false,
			Command::Init { .. }
			| Command::Stack { .. }
			| Command::Db { .. }
			| Command::Service { .. }
			| Command::Limits { .. }
			| Command::Status { .. }
			| Command::Check { .. }
			| Command::Relay { .. }
			| Command::Dns { .. }
			| Command::Storage { .. }
			| Command::Webhook { .. }
			| Command::Alert { .. }
			| Command::Antispam { .. }
			| Command::Alias { .. }
			| Command::Domain { .. }
			| Command::ConfigCheck { .. }
			| Command::Export { .. }
			| Command::Import { .. }
			| Command::Migrate(_)
			| Command::Backup { .. }
			| Command::Restore { .. }
			| Command::Verify { .. }
			| Command::VerifyDns { .. }
			| Command::DnsRecords { .. }
			| Command::Mobileconfig { .. }
			| Command::SrvRecords { .. }
			| Command::Autoconfig { .. }
			| Command::Autodiscover { .. }
			| Command::Suppression { .. }
			| Command::ReportAbuse { .. }
			| Command::Account { .. }
			// Every flat alias reaches a stateful account-side handler.
			| Command::Legacy(_)
			| Command::Queue { .. }
			| Command::Warmup { .. }
			| Command::Delivery { .. }
			| Command::Ban { .. }
			| Command::Masked { .. }
			| Command::AppPassword { .. }
			| Command::Archive { .. }
			| Command::Dkim { .. }
			| Command::Tls { .. }
			| Command::ApiKey { .. }
			| Command::Reports { .. } => true,
			Command::Serve { .. }
			| Command::MtaStsServe { .. }
			| Command::DkimKeygen { .. }
			| Command::StorageKeygen
			| Command::OauthKeygen { .. }
			| Command::TokenHash
			| Command::Local { .. }
			| Command::Probe { .. }
			| Command::Completions { .. }
			| Command::MoveSubids(_)
			| Command::Manpages { .. } => false,
		}
	}
}
