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
use crate::storage::{DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryRecord};

#[path = "delivery_records.rs"]
mod records;
#[path = "delivery_select.rs"]
mod select;

/// `epistle delivery` arguments: the configuration file and the action.
/// The variant in `Command` is a tuple of this struct, so the enum stays
/// under the per-file line ceiling.
#[derive(Debug, Args)]
pub struct DeliveryConfig {
	/// Path to the configuration file; accepted before or after the action.
	#[arg(long, value_name = "FILE", global = true, default_value = DEFAULT_CONFIG_PATH)]
	pub config: PathBuf,
	/// Print the listing as JSON, with or without naming the action.
	#[arg(long)]
	pub json: bool,
	/// Delivery log action (`list`).
	#[command(subcommand)]
	pub action: Option<DeliveryCli>,
}

impl DeliveryConfig {
	/// The action to run: the one named, or the default listing, with
	/// `--json` from this level applied to it.
	pub fn into_action(self) -> Option<DeliveryCli> {
		if !self.json {
			return self.action;
		}
		Some(
			match self
				.action
				.unwrap_or(DeliveryCli::List(ListArgs::default()))
			{
				DeliveryCli::List(args) => DeliveryCli::List(ListArgs { json: true, ..args }),
				DeliveryCli::Show(args) => DeliveryCli::Show(ShowArgs { json: true, ..args }),
				DeliveryCli::Export(args) => DeliveryCli::Export(ExportArgs { json: true, ..args }),
			},
		)
	}
}

/// Actions on the per-recipient delivery log. Without one, `epistle
/// delivery` lists, like `epistle queue` does.
#[derive(Debug, Subcommand)]
pub enum DeliveryCli {
	/// List delivery records (the default when no action is given).
	List(ListArgs),
	/// Show every record of one message.
	Show(ShowArgs),
	/// Write the records that pass the filters as CSV.
	///
	/// One line per record, newest day first: the time as RFC 3339 UTC, the
	/// outcome, the message id, the account, the sender, the recipient, the
	/// remote host and its reply, and the attempt. A field that a spreadsheet
	/// would read as a formula is written with a leading apostrophe.
	Export(ExportArgs),
}

/// `epistle delivery show` arguments.
#[derive(Debug, Args)]
pub struct ShowArgs {
	/// The message id: the spool id in the SPOOL column of `delivery list`.
	pub id: String,
	/// Print one JSON object with the message id and its records.
	#[arg(long)]
	pub json: bool,
}

/// `epistle delivery export` arguments.
#[derive(Debug, Args)]
pub struct ExportArgs {
	/// Print one JSON array instead of CSV.
	#[arg(long)]
	pub json: bool,
	/// Maximum number of records to write, 1 to 100000.
	#[arg(long, value_name = "N", default_value_t = 10_000)]
	pub limit: usize,
	#[command(flatten)]
	pub filters: ListFilters,
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
	/// Upper bound on the record time, in the same forms as `--since`; a
	/// duration counts back from now.
	#[arg(long)]
	pub until: Option<String>,
	/// Restrict to one outcome: `delivered`, `deferred`, `failed`,
	/// `suppressed`, or `canceled`.
	#[arg(long, visible_alias = "status")]
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
	let log = DeliveryLog::open(data_dir, delivery_log_days);
	if !log.is_enabled() {
		style::error(format_args!(
			"the delivery log is disabled; set [storage] delivery_log_days > 0 \
			 (default when enabled: {DEFAULT_DELIVERY_LOG_DAYS})"
		));
		return ExitCode::FAILURE;
	}
	match action.unwrap_or(DeliveryCli::List(ListArgs::default())) {
		DeliveryCli::List(args) => list(&log, &args, now, out),
		DeliveryCli::Show(args) => records::show(&log, &args, out),
		DeliveryCli::Export(args) => records::export(&log, &args, now, out),
	}
}

fn list(log: &DeliveryLog, args: &ListArgs, now: u64, out: &mut impl Write) -> ExitCode {
	let json = args.json;
	if !(1..=records::MAX_EXPORT).contains(&args.limit) {
		style::error(format_args!(
			"--limit must be between 1 and {}",
			records::MAX_EXPORT
		));
		return ExitCode::from(2);
	}
	let selection = match select::Selection::new(&args.filters, now) {
		Ok(selection) => selection,
		Err(code) => return code,
	};
	let records = match log.list_between(Some(args.limit), selection.window(), |record| {
		selection.matches(record)
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
pub(super) struct Row<'a> {
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

impl<'a> From<&'a DeliveryRecord> for Row<'a> {
	fn from(r: &'a DeliveryRecord) -> Self {
		Row {
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
		}
	}
}

fn print_json(records: &[DeliveryRecord], out: &mut impl Write) -> ExitCode {
	let rows: Vec<Row> = records.iter().map(Row::from).collect();
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
