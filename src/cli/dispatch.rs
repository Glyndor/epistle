//! Dispatch every `Command` variant to its handler module.
//!
//! Lives in a sibling so `mod.rs` keeps below the per-file line limit.
//! The match is exhaustive over [`Command`]; adding a variant there
//! without a dispatch arm here is a compile error, which is the same
//! correction the inline dispatch used to give us.

use std::process::ExitCode;

use super::util::{dkim_keygen, message_crypto, oauth_keygen, storage_keygen, token_hash};
use super::{
	Cli, Command, accounts, api_keys, app_passwords, archive, autoconfig, autodiscover, backup,
	dns_records, export, import, mobileconfig, queue, report_abuse, serve, srv, suppression,
	verify, verify_dns,
};
use crate::config::Config;

impl Cli {
	/// Execute the parsed command.
	pub fn run(self) -> ExitCode {
		match self.command {
			Command::Serve { config } => match Config::load(&config) {
				Ok(config) => serve::run(config),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ConfigCheck { config } => match Config::load(&config) {
				Ok(_) => {
					println!("configuration is valid");
					ExitCode::SUCCESS
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Export {
				config,
				account,
				maildir,
			} => match Config::load(&config) {
				Ok(config) => match message_crypto(&config) {
					Ok(crypto) => match maildir {
						Some(dir) => export::run_maildir(&config.data_dir, &account, &crypto, &dir),
						None => export::run(
							&config.data_dir,
							&account,
							&crypto,
							&mut std::io::stdout().lock(),
						),
					},
					Err(code) => code,
				},
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Import {
				config,
				account,
				maildir,
			} => match Config::load(&config) {
				Ok(config) => match message_crypto(&config) {
					Ok(crypto) => match maildir {
						Some(dir) => import::run_maildir(&config.data_dir, &account, &crypto, &dir),
						None => import::run(
							&config.data_dir,
							&account,
							&crypto,
							std::io::stdin().lock(),
						),
					},
					Err(code) => code,
				},
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Backup { config } => match Config::load(&config) {
				Ok(config) => backup::run(
					&config,
					&mut std::io::stdout().lock(),
					&mut std::io::stderr().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Verify { config } => match Config::load(&config) {
				Ok(config) => match message_crypto(&config) {
					Ok(crypto) => {
						verify::run(&config.data_dir, &crypto, &mut std::io::stdout().lock())
					}
					Err(code) => code,
				},
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::VerifyDns { config } => match Config::load(&config) {
				Ok(config) => verify_dns::run(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::DnsRecords { config } => match Config::load(&config) {
				Ok(config) => dns_records::run(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Mobileconfig { config, account } => match Config::load(&config) {
				Ok(config) => mobileconfig::run(&config, &account, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::SrvRecords { config } => match Config::load(&config) {
				Ok(config) => srv::run(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Autoconfig { config, domain } => match Config::load(&config) {
				Ok(config) => {
					autoconfig::run(&config, domain.as_deref(), &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Suppression {
				config,
				remove,
				account,
			} => match Config::load(&config) {
				Ok(config) => suppression::run(
					&config,
					remove.as_deref(),
					account.as_deref(),
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Autodiscover { config, domain } => match Config::load(&config) {
				Ok(config) => {
					autodiscover::run(&config, domain.as_deref(), &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ReportAbuse { config } => match Config::load(&config) {
				Ok(config) => report_abuse::run(
					&config,
					std::io::stdin().lock(),
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Accounts { config } => match Config::load(&config) {
				Ok(config) => accounts::list(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::AccountAdd {
				config,
				name,
				addresses,
			} => match Config::load(&config) {
				Ok(config) => accounts::add(&config, &name, addresses, std::io::stdin().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::AccountRemove {
				config,
				name,
				queue,
			} => match Config::load(&config) {
				Ok(config) => {
					accounts::remove(&config, &name, queue, &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Queue { config } => match Config::load(&config) {
				Ok(config) => queue::list(&config.data_dir, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::DkimKeygen { out, rsa, bits } => dkim_keygen(&out, rsa, bits),
			Command::StorageKeygen => storage_keygen(),
			Command::OauthKeygen => oauth_keygen(),
			Command::TokenHash => token_hash(),
			Command::AppPasswordCreate {
				config,
				account,
				label,
				expires_at,
				ip_cidr,
			} => match Config::load(&config) {
				Ok(config) => app_passwords::create(
					&config,
					&account,
					&label,
					expires_at,
					ip_cidr,
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::AppPasswords { config } => match Config::load(&config) {
				Ok(config) => app_passwords::list(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::AppPasswordRevoke {
				config,
				account,
				label,
			} => match Config::load(&config) {
				Ok(config) => {
					app_passwords::revoke(&config, &account, &label, &mut std::io::stdout().lock())
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ApiKeyCreate {
				config,
				label,
				expires_at,
				ip_cidr,
				scopes,
				domains,
			} => match Config::load(&config) {
				Ok(config) => api_keys::create(
					&config,
					&label,
					expires_at,
					ip_cidr,
					scopes,
					domains,
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ApiKeys { config } => match Config::load(&config) {
				Ok(config) => api_keys::list(&config, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ApiKeyRevoke { config, label } => match Config::load(&config) {
				Ok(config) => api_keys::revoke(&config, &label, &mut std::io::stdout().lock()),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::Archive { action } => archive::dispatch(action, &mut std::io::stdout().lock()),
		}
	}
}
