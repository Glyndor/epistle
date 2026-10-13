//! `epistle delivery list`: per-recipient delivery records from
//! `<data_dir>/deliverylog/`. Metadata only: the subject and the body of
//! any message are never read or printed.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde::Serialize;

use super::style;
use super::term::table::Table;
use crate::storage::{DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryOutcome, DeliveryRecord};

/// `epistle delivery` arguments: the configuration file and the action.
/// The variant in `Command` is a tuple of this struct, so the enum stays
/// under the per-file line ceiling.
#[derive(Debug, Args)]
pub struct DeliveryConfig {
	/// Path to the configuration file; accepted before or after the action.
	#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG_PATH)]
	pub config: PathBuf,
	/// Delivery log action (`list`).
	#[command(subcommand)]
	pub action: Option<DeliveryCli>,
}

/// Actions on the per-recipient delivery log. Without one, `epistle
/// delivery` lists, like `epistle queue` does.
#[derive(Debug, Subcommand)]
pub enum DeliveryCli {
	/// List delivery records (the default when no action is given).
	List(ListArgs),
}

/// `epistle delivery list` arguments.
#[derive(Debug, Args)]
pub struct ListArgs {
	/// Print one JSON array instead of a text table.
	#[arg(long)]
	pub json: bool,
	/// Maximum number of records to print.
	#[arg(long, value_name = "N", default_value_t = DEFAULT_LIMIT)]
	pub limit: usize,
	#[command(flatten)]
	pub filters: ListFilters,
}

impl Default for ListArgs {
	/// What a bare `epistle delivery` lists: every record up to the limit.
	fn default() -> Self {
		Self {
			json: false,
			limit: DEFAULT_LIMIT,
			filters: ListFilters::default(),
		}
	}
}

const DEFAULT_LIMIT: usize = 100;

const DEFAULT_CONFIG_PATH: &str = "/etc/epistle/mail.toml";

/// Filter for `epistle delivery list`. Each field is `None` to skip the
/// corresponding filter, otherwise only records that match every populated
/// field are returned.
#[derive(Debug, Default, Args)]
pub struct ListFilters {
	/// Restrict to a recipient address (the `RCPT TO` value).
	#[arg(long)]
	pub recipient: Option<String>,
	/// Restrict to a sending account (the `MAIL FROM` of the submission).
	#[arg(long)]
	pub account: Option<String>,
	/// Lower bound on the record time: either an RFC 3339 timestamp or a
	/// duration like `24h` / `7d` / `30m` / `5s`. The current wall clock
	/// is the upper bound of the duration.
	#[arg(long)]
	pub since: Option<String>,
	/// Restrict to one outcome: `delivered`, `deferred`, `failed`,
	/// `suppressed`, or `canceled`.
	#[arg(long)]
	pub outcome: Option<String>,
}

/// Run one `epistle delivery` action against the log under `data_dir`;
/// no action lists. `now` is the wall-clock epoch second, injectable so
/// tests can pin the `--since` interpretation. Prints to `out`.
pub(super) fn run(
	data_dir: &Path,
	delivery_log_days: u64,
	action: Option<DeliveryCli>,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	let DeliveryCli::List(args) = action.unwrap_or(DeliveryCli::List(ListArgs::default()));
	list(data_dir, delivery_log_days, &args, now, out)
}

fn list(
	data_dir: &Path,
	delivery_log_days: u64,
	args: &ListArgs,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	let json = args.json;
	let limit = args.limit;
	let filters = &args.filters;
	let log = DeliveryLog::open(data_dir, delivery_log_days);
	if !log.is_enabled() {
		style::error(format_args!(
			"the delivery log is disabled; set [storage] delivery_log_days > 0 \
			 (default when enabled: {DEFAULT_DELIVERY_LOG_DAYS})"
		));
		return ExitCode::FAILURE;
	}
	let outcome_filter = match filters
		.outcome
		.as_deref()
		.map(str::trim)
		.filter(|s| !s.is_empty())
	{
		Some(value) => match DeliveryOutcome::parse(value) {
			Some(outcome) => Some(outcome),
			None => {
				style::error(format_args!(
					"unknown --outcome {value:?}; expected one of delivered, deferred, \
					 failed, suppressed, canceled"
				));
				return ExitCode::from(2);
			}
		},
		None => None,
	};
	let since_epoch = match filters
		.since
		.as_deref()
		.map(str::trim)
		.filter(|s| !s.is_empty())
	{
		Some(value) => match crate::storage::delivery_log::parse_since(value, now) {
			Ok(Some(epoch)) => Some(epoch),
			Ok(None) => None,
			Err(error) => {
				style::error(format_args!("--since {value:?}: {error}"));
				return ExitCode::from(2);
			}
		},
		None => None,
	};
	let recipient_filter = filters
		.recipient
		.as_deref()
		.map(str::trim)
		.filter(|s| !s.is_empty());
	let account_filter = filters
		.account
		.as_deref()
		.map(str::trim)
		.filter(|s| !s.is_empty());

	let outcome_ref = outcome_filter;
	let since_ref = since_epoch;
	let records = match log.list(Some(limit), |record| {
		if let Some(recipient) = recipient_filter
			&& record.recipient != recipient
		{
			return false;
		}
		if let Some(account) = account_filter
			&& record.account.as_deref() != Some(account)
		{
			return false;
		}
		if let Some(since) = since_ref
			&& record.time < since
		{
			return false;
		}
		if let Some(outcome) = outcome_ref
			&& record.outcome != outcome
		{
			return false;
		}
		true
	}) {
		Ok(records) => records,
		Err(error) => {
			style::error(format_args!("reading delivery log: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if json {
		print_json(&records, out)
	} else {
		print_table(&records, out)
	}
}

/// One row of `delivery list --json`: the log record on the wire, with
/// `outcome` rendered as a string the rest of the API and CLI share.
#[derive(Serialize)]
struct Row<'a> {
	time: u64,
	spool_id: &'a uuid::Uuid,
	account: &'a Option<String>,
	from: &'a str,
	recipient: &'a str,
	outcome: &'a str,
	remote: &'a Option<String>,
	reply: &'a Option<String>,
	attempt: u32,
	extra: &'a BTreeMap<String, String>,
}

fn print_json(records: &[DeliveryRecord], out: &mut impl Write) -> ExitCode {
	let rows: Vec<Row> = records
		.iter()
		.map(|r| Row {
			time: r.time,
			spool_id: &r.spool_id,
			account: &r.account,
			from: &r.from,
			recipient: &r.recipient,
			outcome: r.outcome.as_str(),
			remote: &r.remote,
			reply: &r.reply,
			attempt: r.attempt,
			extra: &r.extra,
		})
		.collect();
	match serde_json::to_writer_pretty(&mut *out, &rows) {
		Ok(()) => {
			let _ = writeln!(out);
			ExitCode::SUCCESS
		}
		Err(error) => {
			style::error(format_args!("writing JSON: {error}"));
			ExitCode::FAILURE
		}
	}
}

fn print_table(records: &[DeliveryRecord], out: &mut impl Write) -> ExitCode {
	if records.is_empty() {
		let _ = writeln!(out, "no delivery records matched");
		return ExitCode::SUCCESS;
	}
	let mut table = Table::new(&["TIME", "OUTCOME", "SPOOL", "FROM", "RECIPIENT"]);
	for record in records {
		table.push(vec![
			record.time.to_string(),
			record.outcome.as_str().to_string(),
			record.spool_id.to_string(),
			record.from.clone(),
			record.recipient.clone(),
		]);
	}
	if let Some(decor) = super::term::stdout(false) {
		if let Err(error) = table.write(decor, out) {
			style::error(format_args!("writing table: {error}"));
			return ExitCode::FAILURE;
		}
	} else {
		for record in records {
			let _ = writeln!(
				out,
				"{}\t{}\t{}\t{}\t{}",
				record.time,
				record.outcome.as_str(),
				record.spool_id,
				record.from,
				record.recipient
			);
		}
	}
	let _ = writeln!(out, "{} records", records.len());
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "delivery_tests.rs"]
mod tests;
