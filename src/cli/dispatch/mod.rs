//! Dispatch every `Command` variant to its handler module.
//!
//! Lives in a sibling so `mod.rs` keeps below the per-file line limit.
//! The match is exhaustive over [`Command`]; adding a variant there
//! without a dispatch arm here is a compile error, which is the same
//! correction the inline dispatch used to give us.

use std::path::Path;
use std::process::ExitCode;

use super::term::live;
use super::util::{dkim_keygen, oauth_keygen, storage_keygen, token_hash};
use crate::cli::{
	Cli, Command, account, alias, antispam, api_keys, app::passwords as app_passwords, archive,
	attachments, autoconfig, autodiscover, backup, ban, dkim, dns_records, domain, evidence, init,
	learning, local, mobileconfig, probe, report::abuse as report_abuse, reports, serve, srv,
	stack, status, style, verify::dns as verify_dns,
};
use crate::config::Config;

mod access_ops;
mod delivery_ops;
mod mailbox_data;
mod restore;
mod store_access;
pub(in crate::cli) use restore::dispatch_restore;

/// Run `f` with the loaded config, or surface a `style::error` and the
/// non-zero exit code on a parse failure. The closure shape lets the
/// simple dispatch arms stay one-liners while keeping the failure
/// path identical across them.
pub(super) fn with_config<F: FnOnce(&Config) -> ExitCode>(path: &Path, f: F) -> ExitCode {
	match Config::load(path) {
		Ok(config) => f(&config),
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

impl Cli {
	/// Execute the parsed command.
	pub fn run(self) -> ExitCode {
		crate::cli::config_edit::defer_restarts(self.no_restart);
		if self.command.requires_service_user() {
			match super::rootless::reexecute() {
				Ok(Some(code)) => return code,
				Ok(None) => {}
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			}
		}
		match crate::cli::container::db::reexecute(&self.command) {
			Ok(Some(code)) => return code,
			Ok(None) => {}
			Err(error) => {
				style::error(error);
				return ExitCode::FAILURE;
			}
		}
		let _store = match store_access::guard(&self.command) {
			Ok(guard) => guard,
			Err(error) => {
				style::error(error);
				return ExitCode::FAILURE;
			}
		};
		match self.command {
			Command::MtaStsServe {
				policy_dir,
				cert,
				key,
				listen,
			} => crate::cli::mta::sts_serve::run(policy_dir, cert, key, listen),
			Command::Serve { config, role } => match serve::load(&config, role) {
				Ok(config) => serve::run(config, role),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::ConfigCheck { config, json } => {
				let mut out = std::io::stdout().lock();
				let mut err = style::stderr();
				crate::cli::config::check::run(&config, json, &mut out, &mut err)
			}
			Command::Export {
				config,
				account,
				maildir,
			} => mailbox_data::export(&config, account, maildir),
			Command::Migrate(args) => super::migrate::run(args),
			Command::Import {
				config,
				account,
				maildir,
				json,
			} => mailbox_data::import(&config, account, maildir, json),
			Command::Backup { config } => with_config(&config, |config| {
				backup::run(config, &mut std::io::stdout().lock(), &mut style::stderr())
			}),
			Command::Restore {
				config,
				force,
				dry_run,
				yes,
				json,
			} => dispatch_restore(config, (force, dry_run, yes), json),
			Command::Verify { config, json } => mailbox_data::verify(&config, json),
			Command::VerifyDns { config, json } => with_config(&config, |config| {
				verify_dns::run(config, json, &mut std::io::stdout().lock())
			}),
			Command::DnsRecords { config, json } => with_config(&config, |config| {
				dns_records::run(config, json, &mut std::io::stdout().lock())
			}),
			Command::Mobileconfig { config, account } => with_config(&config, |config| {
				mobileconfig::run(config, &account, &mut std::io::stdout().lock())
			}),
			Command::SrvRecords { config, json } => with_config(&config, |config| {
				srv::run(config, json, &mut std::io::stdout().lock())
			}),
			Command::Autoconfig { config, domain } => with_config(&config, |config| {
				autoconfig::run(config, domain.as_deref(), &mut std::io::stdout().lock())
			}),
			Command::Suppression {
				config,
				json,
				action,
				remove,
				account,
			} => delivery_ops::suppression(&config, json, action, remove, account),
			Command::Autodiscover { config, domain } => with_config(&config, |config| {
				autodiscover::run(config, domain.as_deref(), &mut std::io::stdout().lock())
			}),
			Command::ReportAbuse { config } => with_config(&config, |config| {
				report_abuse::run(
					config,
					std::io::stdin().lock(),
					&mut std::io::stdout().lock(),
				)
			}),
			Command::Legacy(command) => super::legacy::run(command),
			Command::Account {
				config,
				json,
				action,
			} => {
				let mut out = std::io::stdout().lock();
				match Config::load(&config) {
					Ok(_) => account::run(&config, action, json, &mut out),
					Err(error) => {
						style::error(error);
						ExitCode::FAILURE
					}
				}
			}
			Command::Queue {
				config,
				json,
				action,
			} => delivery_ops::queue(&config, json, action),
			Command::Warmup { config, action } => delivery_ops::warmup(&config, action),
			Command::Delivery(args) => delivery_ops::delivery(args),
			Command::Evidence { config, action } => evidence::run(
				&config,
				action,
				ban::now_epoch(),
				&mut std::io::stdout().lock(),
			),
			Command::Ban {
				config,
				json,
				action,
			} => access_ops::ban(&config, json, action),
			Command::Learning { config, action } => match Config::load(&config) {
				Ok(config) => learning::run(&config, action, &mut std::io::stdout().lock()),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Masked {
				config,
				json,
				action,
			} => access_ops::masked(&config, json, action),
			Command::DkimKeygen {
				out,
				rsa,
				bits,
				json,
			} => dkim_keygen(&out, rsa, bits, json),
			Command::StorageKeygen { json } => storage_keygen(json),
			Command::OauthKeygen { out, json } => oauth_keygen(&out, json),
			Command::TokenHash { json } => token_hash(json),
			Command::AppPassword {
				config,
				json,
				action,
			} => match Config::load(&config) {
				Ok(config) => {
					app_passwords::run(&config, action, json, &mut std::io::stdout().lock())
				}
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Archive { json, action } => {
				archive::dispatch(action, json, &mut std::io::stdout().lock())
			}
			Command::Reports { config, days, json } => with_config(&config, |config| {
				reports::run(config, days, json, &mut std::io::stdout().lock())
			}),
			Command::Local { dir, port_base } => local::run(dir, port_base),
			Command::Init {
				answers,
				dry_run,
				print_answers,
				json,
			} => init::run(init::Args {
				answers,
				dry_run,
				print_answers,
				json,
			}),
			Command::Service {
				config,
				action,
				dry_run,
				json,
			} => super::service::run(&config, action, dry_run, json),
			Command::Dns {
				config,
				action,
				dry_run,
				json,
			} => super::dns_provider::run(&config, action, dry_run, json),
			Command::Storage {
				config,
				action,
				dry_run,
				json,
			} => crate::cli::storage::blobs::run(&config, action, dry_run, json),
			Command::Srs {
				config,
				action,
				dry_run,
				json,
			} => crate::cli::srs::run(&config, action, dry_run, json),
			Command::Webhook {
				config,
				action,
				dry_run,
				json,
			} => crate::cli::webhook::admin::run(&config, action, dry_run, json),
			Command::Alert {
				config,
				action,
				dry_run,
				json,
			} => super::alert::run(&config, action, dry_run, json),
			Command::Relay {
				config,
				action,
				dry_run,
				json,
			} => super::relay::run(&config, action, dry_run, json),
			Command::Limits {
				config,
				action,
				dry_run,
			} => super::limits::run(&config, action, dry_run, &mut std::io::stdout().lock()),
			Command::Status { config, json } => live::run("status", json, |mut out| {
				status::run_status(&config, json, &mut out)
			}),
			Command::Check { config, area, json } => {
				live::run(&format!("check {}", area.name()), json, |mut out| {
					status::run_check(&config, area, json, &mut out)
				})
			}
			Command::Antispam {
				config,
				action,
				dry_run,
				json,
			} => antispam::run(&config, action, dry_run, json),
			Command::Attachments {
				config,
				action,
				dry_run,
				json,
			} => attachments::run(&config, action, dry_run, json),
			Command::Alias {
				config,
				action,
				dry_run,
				json,
			} => alias::run(&config, action, dry_run, json),
			Command::Domain {
				config,
				action,
				dry_run,
				json,
			} => domain::run(&config, action, dry_run, json),
			Command::Stack {
				config,
				json,
				action: stack::StackCli::Rollback { to, yes },
			} => super::stack::rollback::run_as_root(&config, to.as_deref(), yes, json),
			Command::Stack {
				config,
				json,
				action,
			} => stack::run_from_path(&config, action, json),
			Command::Dkim {
				config,
				json,
				action,
			} => dkim::dispatch(&config, action, json),
			Command::Tls {
				config,
				json,
				action,
			} => access_ops::tls(&config, json, action),
			Command::ApiKey {
				config,
				json,
				action,
			} => with_config(&config, |config| {
				api_keys::run(config, action, json, &mut std::io::stdout().lock())
			}),
			Command::Probe { config, json } => with_config(&config, |config| {
				live::run("probe", json, |mut out| probe::run(config, json, &mut out))
			}),
			Command::Completions { shell } => super::completions::run_completions(shell),
			Command::Manpages { dir } => super::completions::run_manpages(&dir),
			Command::MoveSubids(args) => super::subid::run(args),
			Command::Db {
				config,
				json,
				action,
			} => match Config::load(&config) {
				Ok(loaded) => super::db_upgrade::run(&loaded, &config, action, json),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
		}
	}
}

#[cfg(test)]
mod tests;
