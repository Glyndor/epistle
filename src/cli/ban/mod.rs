//! `epistle ban`: manage authentication bans and the allow list.
//!
//! Bans live in the PostgreSQL tables the server already uses
//! (`auth_ban`, `auth_failure`, `auth_allow`). The server reads them on every
//! authentication check, so a change made here applies to the running server
//! immediately, with no restart. Without `[database]` there is nothing to
//! manage from outside the process.

use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use serde::Serialize;

use crate::antispam::bans::operator::{self as admin, BanAdmin, Limits, Refusal, StoreError};
use crate::antispam::bans::{BanRow, BanTarget, PgBanStore, UnbanTarget, parse_allow, parse_login};
use crate::cidr::Cidr;
use crate::config::Config;

/// Ban management actions.
#[derive(Debug, Subcommand)]
pub enum BanCli {
	/// List active bans: subject, reason and when each one ends.
	List {
		/// Print a JSON array instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Ban a client address or network by hand.
	Add {
		/// Address (`203.0.113.9`) or network (`203.0.113.0/24`) to ban.
		#[arg(value_parser = BanTarget::parse)]
		target: BanTarget,
		/// How long the ban lasts: a number with a unit `s`, `m`, `h`, `d` or
		/// `w` (for example `90m`, `24h`, `7d`). Defaults to 24h.
		#[arg(long = "for", value_name = "DURATION", value_parser = parse_duration)]
		duration: Option<u64>,
	},
	/// Lift a ban now and clear its failure counter.
	///
	/// Name the ban as `ban list` prints it, or a pair ban by its parts with
	/// `--account` and `--ip`. Quote a `pair:` subject: the shell reads `|` as
	/// a pipe.
	Remove {
		/// Address, network, or subject as `ban list` prints it
		/// (`pair:alice@example.org|203.0.113.9`, `account:alice@example.org`).
		#[arg(
			value_parser = UnbanTarget::parse,
			required_unless_present = "account",
			conflicts_with = "account"
		)]
		target: Option<UnbanTarget>,
		/// Lift the ban on this account as seen from `--ip` (a pair ban).
		#[arg(long, value_name = "LOGIN", value_parser = parse_login, requires = "ip")]
		account: Option<String>,
		/// The client address of the pair named by `--account`.
		#[arg(long, value_name = "ADDRESS", requires = "account")]
		ip: Option<IpAddr>,
	},
	/// Manage the allow list: addresses never banned and never counted.
	Allow {
		/// Allow-list action.
		#[command(subcommand)]
		action: AllowCli,
	},
}

/// Allow-list actions.
#[derive(Debug, Subcommand)]
pub enum AllowCli {
	/// List allowed addresses and networks.
	List {
		/// Print a JSON array instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Never ban this address or network.
	Add {
		/// Address or network to allow.
		#[arg(value_parser = parse_allow)]
		cidr: Cidr,
	},
	/// Take an address or network off the allow list.
	Remove {
		/// Address or network to remove, as it was added.
		#[arg(value_parser = parse_allow)]
		cidr: Cidr,
	},
}

pub(super) use crate::antispam::bans::operator::parse_duration;

/// The current epoch second.
pub(super) fn now_epoch() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Run one ban action. Data goes to `out`, diagnostics to `err`.
pub(super) fn run(
	config: &Config,
	action: BanCli,
	json: bool,
	now: u64,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	let Some(database) = &config.database else {
		super::style::error_to(
			err,
			"no [database] is configured: bans are kept in memory by the running server \
			 and are not manageable from the CLI",
		);
		return ExitCode::FAILURE;
	};
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			super::style::error_to(err, format_args!("starting runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	runtime.block_on(async {
		let pool = match crate::db::connect(
			&database.url,
			database.tls,
			database.max_connections,
			database.password_file.as_deref(),
		)
		.await
		{
			Ok(pool) => pool,
			Err(error) => {
				super::style::error_to(err, error);
				return ExitCode::FAILURE;
			}
		};
		let store = PgBanStore::new(pool, None);
		match execute(&store, action, json, now, out, err).await {
			Ok(code) => code,
			Err(error) => {
				super::style::error_to(err, error);
				ExitCode::FAILURE
			}
		}
	})
}

#[derive(Serialize)]
struct BanJson<'a> {
	subject: &'a str,
	reason: &'a str,
	until: u64,
}

/// The text listing of the bans in force: one line per ban, with the
/// instant it ends and the reason it was raised.
fn render_rows(rows: &[BanRow], out: &mut impl Write) {
	for row in rows {
		let _ = writeln!(
			out,
			"{}\tuntil={}\t{}",
			row.subject,
			crate::clock::rfc3339_or_epoch(row.until_secs),
			row.reason
		);
	}
	let _ = writeln!(out, "{} banned", rows.len());
}

/// The refusal of an operation, said on `err`.
fn refused(refusal: Refusal, err: &mut impl Write) -> Result<ExitCode, StoreError> {
	match refusal {
		Refusal::Store(error) => Err(error),
		other => {
			super::style::error_to(err, other);
			Ok(ExitCode::FAILURE)
		}
	}
}

pub(super) async fn execute(
	store: &dyn BanAdmin,
	action: BanCli,
	json: bool,
	now: u64,
	out: &mut impl Write,
	err: &mut impl Write,
) -> Result<ExitCode, StoreError> {
	match action {
		BanCli::List { json: leaf } => {
			let rows = store.list_bans(now).await?;
			if leaf || json {
				let rows: Vec<BanJson> = rows
					.iter()
					.map(|r| BanJson {
						subject: &r.subject,
						reason: &r.reason,
						until: r.until_secs,
					})
					.collect();
				print_json(&rows, out, err)
			} else {
				render_rows(&rows, out);
				Ok(ExitCode::SUCCESS)
			}
		}
		BanCli::Add { target, duration } => {
			let banned = match admin::ban(store, target, duration, now, Limits::operator()).await {
				Ok(banned) => banned,
				Err(refusal) => return refused(refusal, err),
			};
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!(
				"banned {target} until {}",
				crate::clock::rfc3339_or_epoch(banned.until)
			));
			let fields = serde_json::json!({ "target": banned.target, "until": banned.until });
			Ok(report.change("add", true, fields, None))
		}
		BanCli::Remove {
			target,
			account,
			ip,
		} => {
			let target = match (target, account) {
				(Some(target), _) => target,
				(None, Some(account)) => match UnbanTarget::pair(&account, ip) {
					Ok(target) => target,
					Err(error) => {
						super::style::error_to(err, error);
						return Ok(ExitCode::FAILURE);
					}
				},
				(None, None) => {
					super::style::error_to(err, "name the ban to lift");
					return Ok(ExitCode::FAILURE);
				}
			};
			let unbanned = match admin::unban(store, target, Limits::operator()).await {
				Ok(unbanned) => unbanned,
				Err(refusal) => return refused(refusal, err),
			};
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!(
				"unbanned {} ({} bans, {} failures cleared)",
				unbanned.target, unbanned.bans, unbanned.failures
			));
			let fields = serde_json::json!({
				"target": unbanned.target, "bans": unbanned.bans, "failures": unbanned.failures,
			});
			Ok(report.change("remove", true, fields, None))
		}
		BanCli::Allow { action } => allow(store, action, json, out, err).await,
	}
}

async fn allow(
	store: &dyn BanAdmin,
	action: AllowCli,
	json: bool,
	out: &mut impl Write,
	err: &mut impl Write,
) -> Result<ExitCode, StoreError> {
	match action {
		AllowCli::List { json: leaf } => {
			let entries = store.allow_list().await?;
			if leaf || json {
				return print_json(&entries, out, err);
			}
			for entry in &entries {
				let _ = writeln!(out, "{entry}");
			}
			let _ = writeln!(out, "{} allowed", entries.len());
			Ok(ExitCode::SUCCESS)
		}
		AllowCli::Add { cidr } => {
			let added = match admin::allow(store, cidr, Limits::operator()).await {
				Ok(added) => added,
				Err(refusal) => return refused(refusal, err),
			};
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!(
				"{} {cidr}",
				if added { "allowed" } else { "already allowed" }
			));
			let fields = serde_json::json!({ "cidr": cidr.to_string() });
			Ok(report.change("allow add", added, fields, None))
		}
		AllowCli::Remove { cidr } => match admin::disallow(store, cidr, Limits::operator()).await {
			Ok(()) => {
				let mut report = super::json_out::Report::new(out, json);
				report.line(format_args!("removed {cidr} from the allow list"));
				let fields = serde_json::json!({ "cidr": cidr.to_string() });
				Ok(report.change("allow remove", true, fields, None))
			}
			Err(refusal) => refused(refusal, err),
		},
	}
}

fn print_json(
	value: &impl Serialize,
	out: &mut impl Write,
	err: &mut impl Write,
) -> Result<ExitCode, StoreError> {
	match serde_json::to_writer_pretty(&mut *out, value) {
		Ok(()) => {
			let _ = writeln!(out);
			Ok(ExitCode::SUCCESS)
		}
		Err(error) => {
			super::style::error_to(err, format_args!("writing JSON: {error}"));
			Ok(ExitCode::FAILURE)
		}
	}
}

#[cfg(test)]
mod tests;
