//! `epistle delivery show` and `epistle delivery export`.
//!
//! Both print what the delivery log holds, which includes text a remote
//! server chose (its host name and its reply), so every such value is
//! escaped before it reaches a terminal or a spreadsheet.

use std::io::Write;
use std::process::ExitCode;

use uuid::Uuid;

use super::select::Selection;
use super::{ExportArgs, Row, ShowArgs, style};
use crate::cli::csv::field;
use crate::cli::json_out;
use crate::cli::term::sanitize;
use crate::storage::{DeliveryLog, DeliveryRecord};

/// The most records `delivery show` prints for one message.
const MAX_SHOWN: usize = 10_000;
/// The most records one `delivery export` writes.
pub(super) const MAX_EXPORT: usize = 100_000;

fn stamp(time: u64) -> String {
	crate::clock::rfc3339(time)
}

fn dash(value: &Option<String>) -> String {
	value.as_deref().map_or_else(|| "-".to_string(), sanitize)
}

fn failed(error: impl std::fmt::Display) -> ExitCode {
	style::error(format_args!("reading delivery log: {error}"));
	ExitCode::FAILURE
}

/// `delivery show ID`: every record of one message, oldest first.
pub(super) fn show(log: &DeliveryLog, args: &ShowArgs, out: &mut impl Write) -> ExitCode {
	let Ok(id) = args.id.trim().parse::<Uuid>() else {
		style::error(format_args!(
			"{:?} is not a message id (a UUID such as the SPOOL column of `delivery list`)",
			sanitize(&crate::util::address_reason::shorten(&args.id))
		));
		return ExitCode::from(2);
	};
	let mut records = match log.list(Some(MAX_SHOWN), |record| record.spool_id == id) {
		Ok(records) => records,
		Err(error) => return failed(error),
	};
	if records.is_empty() {
		style::error(format_args!("no delivery records for {id}"));
		return ExitCode::from(2);
	}
	records.sort_by_key(|record| record.time);
	if args.json {
		let rows: Vec<Row> = records.iter().map(Row::from).collect();
		let object = serde_json::json!({ "spool_id": id, "records": rows });
		return json_out::print(out, &object);
	}
	let mut text = format!("message\t{id}\nrecords\t{}\n", records.len());
	for record in &records {
		text.push_str(&format!(
			"\ntime\t{}\noutcome\t{}\naccount\t{}\nfrom\t{}\nrecipient\t{}\nremote\t{}\nreply\t{}\nattempt\t{}\n",
			stamp(record.time),
			record.outcome.as_str(),
			dash(&record.account),
			sanitize(&record.from),
			sanitize(&record.recipient),
			dash(&record.remote),
			dash(&record.reply),
			record.attempt,
		));
	}
	match out.write_all(text.as_bytes()) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			style::error(format_args!("writing output: {error}"));
			ExitCode::FAILURE
		}
	}
}

fn csv_line(record: &DeliveryRecord) -> String {
	[
		stamp(record.time),
		record.outcome.as_str().to_string(),
		record.spool_id.to_string(),
		field(record.account.as_deref().unwrap_or("")),
		field(&record.from),
		field(&record.recipient),
		field(record.remote.as_deref().unwrap_or("")),
		field(record.reply.as_deref().unwrap_or("")),
		record.attempt.to_string(),
	]
	.join(",")
}

/// `delivery export`: the records that pass the filters as CSV, newest day
/// first like `delivery list`, or with `--json` as one array.
pub(super) fn export(
	log: &DeliveryLog,
	args: &ExportArgs,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	if !(1..=MAX_EXPORT).contains(&args.limit) {
		style::error(format_args!("--limit must be between 1 and {MAX_EXPORT}"));
		return ExitCode::from(2);
	}
	let selection = match Selection::new(&args.filters, now) {
		Ok(selection) => selection,
		Err(code) => return code,
	};
	let records = match log.list_between(Some(args.limit), selection.window(), |record| {
		selection.matches(record)
	}) {
		Ok(records) => records,
		Err(error) => return failed(error),
	};
	if args.json {
		let rows: Vec<Row> = records.iter().map(Row::from).collect();
		return match serde_json::to_value(&rows) {
			Ok(value) => json_out::print(out, &value),
			Err(error) => failed(error),
		};
	}
	let mut text =
		String::from("time,outcome,spool_id,account,from,recipient,remote,reply,attempt\n");
	for record in &records {
		text.push_str(&csv_line(record));
		text.push('\n');
	}
	match out.write_all(text.as_bytes()) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			style::error(format_args!("writing output: {error}"));
			ExitCode::FAILURE
		}
	}
}
