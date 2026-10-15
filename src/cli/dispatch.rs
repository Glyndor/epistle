//! Dispatch every `Command` variant to its handler module.
//!
//! Lives in a sibling so `mod.rs` keeps below the per-file line limit.
//! The match is exhaustive over [`Command`]; adding a variant there
//! without a dispatch arm here is a compile error, which is the same
//! correction the inline dispatch used to give us.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use super::term::live;
use super::util::{dkim_keygen, message_crypto, oauth_keygen, storage_keygen, token_hash};
use super::{
	Cli, Command, account, alias, antispam, api_keys, app_passwords, archive, autoconfig,
	autodiscover, backup, ban, delivery, dkim_cli, dns_records, domain, export, import, init,
	local, masked, mobileconfig, probe, queue, report_abuse, reports, serve, srv, stack, status,
	style, suppression, tls_cli, verify, verify_dns, warmup,
};
use crate::config::Config;

/// Run the `restore` subcommand: read the archive from stdin, load the
/// config, hand the bytes to [`backup::run_restore`]. Lives here rather
/// than in the match arm so the dispatch table stays compact and the
/// per-file line budget keeps `dispatch.rs` under 500 code lines.
pub(super) fn dispatch_restore(config: PathBuf, force: bool, dry_run: bool, yes: bool) -> ExitCode {
	let config = match Config::load(&config) {
		Ok(config) => config,
		Err(error) => {
			style::error(error);
			return ExitCode::FAILURE;
		}
	};
	// stdin carries the archive, so the question is answered on the
	// terminal. `--yes` answers it; it never stands in for `--force`, and
	// the restore still refuses an unsafe target without `--force`.
	let question = format!(
		"Restore the archive on stdin into {}, replacing what is there? [y/N]",
		config.data_dir.display()
	);
	if !dry_run
		&& let Err(code) = super::prompt::confirm_destructive_on_terminal("restore", &question, yes)
	{
		return code;
	}
	let mut input = Vec::new();
	if let Err(error) = std::io::Read::read_to_end(&mut super::prompt::stdin(), &mut input) {
		style::error(format_args!("reading archive from stdin: {error}"));
		return ExitCode::FAILURE;
	}
	backup::run_restore(
		&config,
		&input,
		force,
		dry_run,
		&mut std::io::stdout().lock(),
		&mut style::stderr(),
	)
}

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
		match super::container_db::reexecute(&self.command) {
			Ok(Some(code)) => return code,
			Ok(None) => {}
			Err(error) => {
				style::error(error);
				return ExitCode::FAILURE;
			}
		}
		match self.command {
			Command::MtaStsServe {
				policy_dir,
				cert,
				key,
				listen,
			} => super::mta_sts_serve::run(policy_dir, cert, key, listen),
			Command::Serve { config } => match Config::load(&config) {
				Ok(config) => serve::run(config),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::ConfigCheck { config } => {
				let mut out = std::io::stdout().lock();
				let mut err = style::stderr();
				super::config_check::run(&config, &mut out, &mut err)
			}
			Command::Export {
				config,
				account,
				maildir,
			} => match Config::load(&config) {
				Ok(config) => match message_crypto(&config) {
					Ok(crypto) => {
						live::run(
							&format!("export {account}"),
							false,
							|mut out| match maildir {
								Some(dir) => {
									export::run_maildir(&config.data_dir, &account, &crypto, &dir)
								}
								None => export::run(&config.data_dir, &account, &crypto, &mut out),
							},
						)
					}
					Err(code) => code,
				},
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Migrate(args) => super::migrate::run(args),
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
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Backup { config } => with_config(&config, |config| {
				backup::run(config, &mut std::io::stdout().lock(), &mut style::stderr())
			}),
			Command::Restore {
				config,
				force,
				dry_run,
				yes,
			} => dispatch_restore(config, force, dry_run, yes),
			Command::Verify { config } => match Config::load(&config) {
				Ok(config) => match message_crypto(&config) {
					Ok(crypto) => live::run("verify", false, |mut out| {
						verify::run(&config.data_dir, &crypto, &mut out)
					}),
					Err(code) => code,
				},
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::VerifyDns { config } => with_config(&config, |config| {
				verify_dns::run(config, &mut std::io::stdout().lock())
			}),
			Command::DnsRecords { config } => with_config(&config, |config| {
				dns_records::run(config, &mut std::io::stdout().lock())
			}),
			Command::Mobileconfig { config, account } => with_config(&config, |config| {
				mobileconfig::run(config, &account, &mut std::io::stdout().lock())
			}),
			Command::SrvRecords { config } => with_config(&config, |config| {
				srv::run(config, &mut std::io::stdout().lock())
			}),
			Command::Autoconfig { config, domain } => with_config(&config, |config| {
				autoconfig::run(config, domain.as_deref(), &mut std::io::stdout().lock())
			}),
			Command::Suppression {
				config,
				action,
				remove,
				account,
			} => match Config::load(&config) {
				Ok(config) => match action {
					Some(action) => {
						suppression::run(&config, action, &mut std::io::stdout().lock())
					}
					None => suppression::run_legacy(
						&config,
						remove.as_deref(),
						account.as_deref(),
						&mut std::io::stdout().lock(),
					),
				},
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
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
			Command::Queue { config, action } => match Config::load(&config) {
				Ok(config) => {
					let webhook = config.webhook.as_ref().map(|wh| {
						Arc::new(
							crate::webhook::Webhook::new(&wh.url, wh.secret.clone())
								.expect("webhook"),
						)
					});
					queue::run(
						&config.data_dir,
						config.storage.as_ref(),
						config.delivery_log_days(),
						action,
						queue::now_epoch(),
						webhook.as_ref(),
						&mut std::io::stdout().lock(),
					)
				}
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Warmup { config, action } => match Config::load(&config) {
				Ok(config) => warmup::run(
					&config.data_dir,
					config.storage.as_ref(),
					config.delivery_log_days(),
					&crate::queue::warmup::relay_hosts(&config.transport),
					action,
					queue::now_epoch(),
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Delivery(args) => match Config::load(&args.config) {
				Ok(config) => delivery::run(
					&config.data_dir,
					config.delivery_log_days(),
					args.action,
					queue::now_epoch(),
					&mut std::io::stdout().lock(),
				),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Ban { config, action } => match Config::load(&config) {
				Ok(config) => ban::run(
					&config,
					action,
					ban::now_epoch(),
					&mut std::io::stdout().lock(),
					&mut style::stderr(),
				),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Masked { config, action } => match Config::load(&config) {
				Ok(config) => masked::run(
					&config,
					action,
					ban::now_epoch(),
					&mut std::io::stdout().lock(),
					&mut style::stderr(),
				),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::DkimKeygen { out, rsa, bits } => dkim_keygen(&out, rsa, bits),
			Command::StorageKeygen => storage_keygen(),
			Command::OauthKeygen { out } => oauth_keygen(&out),
			Command::TokenHash => token_hash(),
			Command::AppPassword { config, action } => match Config::load(&config) {
				Ok(config) => app_passwords::run(&config, action, &mut std::io::stdout().lock()),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Archive { action } => archive::dispatch(action, &mut std::io::stdout().lock()),
			Command::Reports { config, days } => with_config(&config, |config| {
				reports::run(config, days, &mut std::io::stdout().lock())
			}),
			Command::Local { dir, port_base } => local::run(dir, port_base),
			Command::Init {
				answers,
				dry_run,
				print_answers,
			} => init::run(init::Args {
				answers,
				dry_run,
				print_answers,
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
			} => super::storage_blobs::run(&config, action, dry_run, json),
			Command::Webhook {
				config,
				action,
				dry_run,
				json,
			} => super::webhook_admin::run(&config, action, dry_run, json),
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
				action: stack::StackCli::Rollback { to, yes },
			} => super::stack_rollback::run_as_root(&config, to.as_deref(), yes),
			Command::Stack { config, action } => match Config::load(&config) {
				Ok(config) => stack::run(&config, action.into()),
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Dkim { config, action } => match Config::load(&config) {
				Ok(config) => match action {
					action @ dkim_cli::DkimCli::Rotate { .. } => {
						live::run("dkim rotate", false, |mut out| {
							dkim_cli::run(&config, action, &mut out)
						})
					}
					action => dkim_cli::run(&config, action, &mut std::io::stdout().lock()),
				},
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::Tls { config, action } => match Config::load(&config) {
				Ok(config) => match action {
					action @ tls_cli::TlsCli::Renew { .. } => {
						live::run("tls renew", false, |mut out| {
							tls_cli::run(&config, action, &mut out)
						})
					}
					action => tls_cli::run(&config, action, &mut std::io::stdout().lock()),
				},
				Err(error) => {
					style::error(error);
					ExitCode::FAILURE
				}
			},
			Command::ApiKey { config, action } => with_config(&config, |config| {
				api_keys::run(config, action, &mut std::io::stdout().lock())
			}),
			Command::Probe { config, json } => with_config(&config, |config| {
				live::run("probe", json, |mut out| probe::run(config, json, &mut out))
			}),
			Command::Completions { shell } => super::completions::run_completions(shell),
			Command::Manpages { dir } => super::completions::run_manpages(&dir),
			Command::MoveSubids(args) => super::subid::run(args),
			Command::Db { config, action } => {
				with_config(&config, |config| super::db_upgrade::run(config, action))
			}
		}
	}
}

#[cfg(test)]
#[path = "dispatch_tests_delegation.rs"]
mod tests_delegation;
