//! `epistle ban`: manage authentication bans and the allow list.
//!
//! Bans live in the PostgreSQL tables the server already uses
//! (`auth_ban`, `auth_failure`, `auth_allow`). The server reads them on every
//! authentication check, so a change made here applies to the running server
//! immediately, with no restart. Without `[database]` there is nothing to
//! manage from outside the process.

use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use serde::Serialize;

use crate::antispam::bans::{BanTarget, PgBanStore, parse_allow};
use crate::cidr::Cidr;
use crate::config::Config;

/// Default length of a manual ban when `--for` is not given.
const DEFAULT_BAN_SECS: u64 = 24 * 3600;
/// Longest manual ban accepted: keeps the end time far from timestamp limits.
const MAX_BAN_SECS: u64 = 10 * 365 * 24 * 3600;

/// Ban management actions.
#[derive(Debug, Subcommand)]
pub enum BanCli {
	/// List active bans: subject, reason and the epoch second each one ends.
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
	/// Lift a ban now and clear the address's failure counter.
	Remove {
		/// Address or network whose ban to lift.
		#[arg(value_parser = BanTarget::parse)]
		target: BanTarget,
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

/// Parse `<number><unit>` into seconds (`s`, `m`, `h`, `d`, `w`; a bare number
/// is seconds). Zero and anything above ten years are refused.
pub(super) fn parse_duration(text: &str) -> Result<u64, String> {
	let text = text.trim();
	let split = text
		.find(|c: char| !c.is_ascii_digit())
		.unwrap_or(text.len());
	let (digits, unit) = text.split_at(split);
	let count: u64 = digits
		.parse()
		.map_err(|_| format!("{text:?} is not a duration; use a number and a unit, like 24h"))?;
	let unit_secs = match unit {
		"" | "s" => 1,
		"m" => 60,
		"h" => 3600,
		"d" => 86_400,
		"w" => 604_800,
		other => {
			return Err(format!(
				"unknown duration unit {other:?}; use s, m, h, d or w"
			));
		}
	};
	let secs = count.saturating_mul(unit_secs);
	if secs == 0 || secs > MAX_BAN_SECS {
		return Err("a ban lasts between 1 second and 10 years".to_string());
	}
	Ok(secs)
}

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
				super::style::error_to(err, format_args!("database: {error}"));
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

async fn execute(
	store: &PgBanStore,
	action: BanCli,
	json: bool,
	now: u64,
	out: &mut impl Write,
	err: &mut impl Write,
) -> Result<ExitCode, sqlx::Error> {
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
				for row in &rows {
					let _ = writeln!(
						out,
						"{}\tuntil={}\t{}",
						row.subject, row.until_secs, row.reason
					);
				}
				let _ = writeln!(out, "{} banned", rows.len());
				Ok(ExitCode::SUCCESS)
			}
		}
		BanCli::Add { target, duration } => {
			if let BanTarget::Ip(ip) = target
				&& store
					.allow_list()
					.await?
					.iter()
					.any(|entry| Cidr::parse(entry).is_some_and(|cidr| cidr.contains(ip)))
			{
				super::style::error_to(
					err,
					format_args!(
						"{ip} is on the allow list, which overrides every ban; remove it there first"
					),
				);
				return Ok(ExitCode::FAILURE);
			}
			let until = now.saturating_add(duration.unwrap_or(DEFAULT_BAN_SECS));
			store.add_ban(target, now, until).await?;
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!("banned {target} until {until}"));
			let fields = serde_json::json!({ "target": target.to_string(), "until": until });
			Ok(report.change("add", true, fields, None))
		}
		BanCli::Remove { target } => {
			let (bans, failures) = store.remove_ban(target).await?;
			if bans == 0 && failures == 0 {
				super::style::error_to(err, format_args!("{target} has no ban or failure record"));
				return Ok(ExitCode::FAILURE);
			}
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!(
				"unbanned {target} ({bans} bans, {failures} failures cleared)"
			));
			let fields = serde_json::json!({
				"target": target.to_string(), "bans": bans, "failures": failures,
			});
			Ok(report.change("remove", true, fields, None))
		}
		BanCli::Allow { action } => allow(store, action, json, out, err).await,
	}
}

async fn allow(
	store: &PgBanStore,
	action: AllowCli,
	json: bool,
	out: &mut impl Write,
	err: &mut impl Write,
) -> Result<ExitCode, sqlx::Error> {
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
			let added = store.allow_add(cidr).await?;
			let mut report = super::json_out::Report::new(out, json);
			report.line(format_args!(
				"{} {cidr}",
				if added { "allowed" } else { "already allowed" }
			));
			let fields = serde_json::json!({ "cidr": cidr.to_string() });
			Ok(report.change("allow add", added, fields, None))
		}
		AllowCli::Remove { cidr } => {
			if store.allow_remove(cidr).await? {
				let mut report = super::json_out::Report::new(out, json);
				report.line(format_args!("removed {cidr} from the allow list"));
				let fields = serde_json::json!({ "cidr": cidr.to_string() });
				Ok(report.change("allow remove", true, fields, None))
			} else {
				super::style::error_to(err, format_args!("{cidr} is not on the allow list"));
				Ok(ExitCode::FAILURE)
			}
		}
	}
}

fn print_json(
	value: &impl Serialize,
	out: &mut impl Write,
	err: &mut impl Write,
) -> Result<ExitCode, sqlx::Error> {
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
#[path = "ban_tests.rs"]
mod tests;
