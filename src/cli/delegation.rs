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
			Command::Init { .. }
			| Command::Stack { .. }
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
			| Command::Accounts { .. }
			| Command::AccountAdd { .. }
			| Command::AccountRemove { .. }
			| Command::Account { .. }
			| Command::Queue { .. }
			| Command::Ban { .. }
			| Command::Masked { .. }
			| Command::AppPasswordCreate { .. }
			| Command::AppPasswords { .. }
			| Command::AppPasswordRevoke { .. }
			| Command::ApiKeyCreate { .. }
			| Command::ApiKeys { .. }
			| Command::ApiKeyRevoke { .. }
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
			| Command::Probe { .. } => false,
		}
	}
}
