//! `epistle suppression show|export|import`: read one entry, write the list
//! out as CSV and load such a file back.
//!
//! The exchange format is a header line `address,since,reason` followed by
//! one entry per line: the address, when it was suppressed as an RFC 3339
//! UTC time (empty when not recorded) and why. A line holding only an
//! address is an entry too, and blank lines and lines starting with `#` are
//! skipped, so a plain list of addresses imports as it is. An import is
//! checked whole before anything is written: one bad line refuses the file.

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::super::resource::{self, ResourceError};
use super::super::term::sanitize;
use crate::config::Config;
use crate::queue::{Suppressed, SuppressionList};

/// The largest file an import reads: the staging limit for a file read by a
/// root run, so an import behaves the same with or without `sudo`.
const MAX_BYTES: u64 = 16 * 1024 * 1024;
/// The most entries one import accepts. Each becomes a file on disk.
const MAX_ENTRIES: usize = 100_000;
/// The longest stored reason, in characters (what a marker keeps).
pub(super) const MAX_REASON: usize = 512;
/// How many bad lines an import names before it stops listing them.
const MAX_PROBLEMS: usize = 10;
/// Reason recorded for an imported line that carries none.
const IMPORTED: &str = "imported (epistle suppression import)";

/// One validated line of an import.
#[derive(Debug, PartialEq, Eq)]
struct Row {
	address: String,
	since: Option<u64>,
	reason: Option<String>,
}

/// Why a reason cannot be stored as given, or `None` when it can.
pub(super) fn reason_problem(reason: &str) -> Option<String> {
	if reason.chars().any(char::is_control) {
		return Some("the reason must not contain control characters".into());
	}
	if reason.chars().count() > MAX_REASON {
		return Some(format!(
			"the reason must be at most {MAX_REASON} characters"
		));
	}
	None
}

fn open(config: &Config) -> Result<SuppressionList, ResourceError> {
	SuppressionList::open(&config.data_dir)
		.map_err(|error| ResourceError::Failure(format!("cannot open suppression list: {error}")))
}

fn entries(list: &SuppressionList, account: Option<&str>) -> Vec<Suppressed> {
	match account {
		Some(account) => list.entries_for(account),
		None => list.entries(),
	}
}

fn stamp(since: Option<u64>) -> Option<String> {
	since.map(crate::clock::rfc3339)
}

fn failure(error: std::io::Error) -> ResourceError {
	ResourceError::Failure(error.to_string())
}

/// `suppression show ADDRESS`.
pub(super) fn show(
	config: &Config,
	address: &str,
	account: Option<&str>,
	json: bool,
	out: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	let parsed = crate::util::address_reason::parse(address)
		.map_err(|why| ResourceError::refused(format!("cannot show: {why}")))?;
	let address = crate::util::address::normalize(&parsed.to_string());
	let list = open(config)?;
	let entry = match account {
		Some(account) => list.entry_for(account, &address),
		None => list.entry(&address),
	};
	let entry = entry.ok_or_else(|| {
		ResourceError::refused(format!("{} is not suppressed", sanitize(&address)))
	})?;
	let since = stamp(entry.since);
	if json {
		let object = json!({
			"address": entry.address, "account": account, "suppressed": true,
			"since": since, "reason": entry.reason,
		});
		resource::json(out, &object).map_err(ResourceError::Failure)?;
		return Ok(ExitCode::SUCCESS);
	}
	let scope = account.map_or_else(
		|| "global".to_string(),
		|account| format!("account {account}"),
	);
	let none = "-".to_string();
	write!(
		out,
		"address\t{}\nscope\t{scope}\nsince\t{}\nreason\t{}\n",
		sanitize(&entry.address),
		since.unwrap_or_else(|| none.clone()),
		sanitize(&entry.reason.unwrap_or(none)),
	)
	.map_err(failure)?;
	Ok(ExitCode::SUCCESS)
}

/// A CSV field: quoted when it holds a comma, a quote or a leading or
/// trailing space, and prefixed with an apostrophe when a spreadsheet would
/// read it as a formula. `import` removes that apostrophe.
fn field(text: &str) -> String {
	let flat: String = text
		.chars()
		.map(|c| if c.is_control() { ' ' } else { c })
		.collect();
	let flat = if flat.starts_with(['=', '+', '-', '@']) {
		format!("'{flat}")
	} else {
		flat
	};
	if flat.contains([',', '"']) || flat != flat.trim() {
		format!("\"{}\"", flat.replace('"', "\"\""))
	} else {
		flat
	}
}

/// `suppression export`: CSV on stdout, or with `--json` the same entries
/// as one array.
pub(super) fn export(
	config: &Config,
	account: Option<&str>,
	json: bool,
	out: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	let rows = entries(&open(config)?, account);
	if json {
		let rows: Vec<_> = rows
			.iter()
			.map(
				|row| json!({"address": row.address, "since": stamp(row.since), "reason": row.reason}),
			)
			.collect();
		resource::json(out, &rows).map_err(ResourceError::Failure)?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(out, "address,since,reason").map_err(failure)?;
	for row in rows {
		writeln!(
			out,
			"{},{},{}",
			field(&row.address),
			stamp(row.since).unwrap_or_default(),
			field(row.reason.as_deref().unwrap_or("")),
		)
		.map_err(failure)?;
	}
	Ok(ExitCode::SUCCESS)
}

/// Split one CSV line into its fields. A field may be quoted, with `""` for
/// a quote inside; a quote anywhere else, or text after a closing quote, is
/// an error.
fn split(line: &str) -> Result<Vec<String>, &'static str> {
	let mut fields = Vec::new();
	let mut chars = line.chars().peekable();
	loop {
		let mut value = String::new();
		if chars.peek() == Some(&'"') {
			chars.next();
			loop {
				match chars.next() {
					None => return Err("a quoted field is not closed"),
					Some('"') if chars.peek() == Some(&'"') => {
						chars.next();
						value.push('"');
					}
					Some('"') => break,
					Some(c) => value.push(c),
				}
			}
			if !matches!(chars.peek(), None | Some(',')) {
				return Err("text follows a closing quote");
			}
		} else {
			while let Some(&c) = chars.peek() {
				if c == ',' {
					break;
				}
				if c == '"' {
					return Err("a quote inside an unquoted field");
				}
				value.push(c);
				chars.next();
			}
		}
		fields.push(value);
		if chars.next().is_none() {
			return Ok(fields);
		}
	}
}

/// `'=…` back to `=…`: the apostrophe `export` put before a formula.
fn unquote_formula(text: &str) -> &str {
	match text.strip_prefix('\'') {
		Some(rest) if rest.starts_with(['=', '+', '-', '@']) => rest,
		_ => text,
	}
}

/// One data line, or why it is refused.
fn parse_row(line: &str, now: u64) -> Result<Row, String> {
	let fields = split(line).map_err(str::to_string)?;
	if fields.len() > 3 {
		return Err("more than three fields (address, since, reason)".into());
	}
	let address = unquote_formula(fields[0].trim());
	let parsed = crate::util::address_reason::parse(address)?;
	let since = match fields
		.get(1)
		.map(|text| text.trim())
		.filter(|text| !text.is_empty())
	{
		None => None,
		Some(text) => Some(
			crate::storage::delivery_log::parse_rfc3339(text)
				.map(|epoch| epoch.min(now))
				.map_err(|_| {
					format!(
						"the time must be RFC 3339 UTC, like 2026-01-02T03:04:05Z (got {})",
						crate::util::address_reason::shorten(&sanitize(text))
					)
				})?,
		),
	};
	let reason = fields
		.get(2)
		.map(|text| unquote_formula(text.trim()))
		.filter(|text| !text.is_empty());
	if let Some(problem) = reason.and_then(reason_problem) {
		return Err(problem);
	}
	Ok(Row {
		address: crate::util::address::normalize(&parsed.to_string()),
		since,
		reason: reason.map(str::to_string),
	})
}

/// Every row of `text`, or the lines that refuse it. Stops reading at
/// [`MAX_ENTRIES`] data lines.
fn parse(text: &str, now: u64) -> Result<Vec<Row>, Vec<String>> {
	let mut rows = Vec::new();
	let mut problems = Vec::new();
	let mut data_lines = 0_usize;
	let mut first = true;
	for (index, line) in text
		.strip_prefix('\u{feff}')
		.unwrap_or(text)
		.lines()
		.enumerate()
	{
		let line = line.trim_end();
		if line.trim().is_empty() || line.starts_with('#') {
			continue;
		}
		if first && line.eq_ignore_ascii_case("address,since,reason") {
			first = false;
			continue;
		}
		first = false;
		data_lines += 1;
		if data_lines > MAX_ENTRIES {
			return Err(vec![format!(
				"more than {MAX_ENTRIES} entries; split the file"
			)]);
		}
		match parse_row(line, now) {
			Ok(row) => rows.push(row),
			Err(why) if problems.len() < MAX_PROBLEMS => {
				problems.push(format!("line {}: {}", index + 1, sanitize(&why)));
			}
			Err(_) => {}
		}
	}
	if problems.is_empty() {
		Ok(rows)
	} else {
		Err(problems)
	}
}

/// The text of an import file, read within [`MAX_BYTES`].
fn read_input(path: &Path) -> Result<String, ResourceError> {
	let shown = sanitize(&path.display().to_string());
	let mut file = std::fs::File::open(path).map_err(|error| {
		let message = format!("cannot read {shown}: {error}");
		if error.kind() == std::io::ErrorKind::NotFound {
			ResourceError::refused(message)
		} else {
			ResourceError::Failure(message)
		}
	})?;
	let metadata = file.metadata().map_err(failure)?;
	if !metadata.is_file() {
		return Err(ResourceError::refused(format!(
			"{shown} is not a regular file"
		)));
	}
	let too_big = || ResourceError::refused(format!("{shown} is larger than 16 MiB; split it"));
	if metadata.len() > MAX_BYTES {
		return Err(too_big());
	}
	let mut bytes = Vec::new();
	(&mut file)
		.take(MAX_BYTES + 1)
		.read_to_end(&mut bytes)
		.map_err(failure)?;
	if bytes.len() as u64 > MAX_BYTES {
		return Err(too_big());
	}
	String::from_utf8(bytes)
		.map_err(|_| ResourceError::refused(format!("{shown} is not UTF-8 text")))
}

/// What an import will do, or did.
struct Plan {
	add: Vec<Row>,
	already: usize,
	duplicates: usize,
}

fn plan(list: &SuppressionList, account: Option<&str>, rows: Vec<Row>) -> Plan {
	let mut seen = std::collections::HashSet::new();
	let mut plan = Plan {
		add: Vec::new(),
		already: 0,
		duplicates: 0,
	};
	for row in rows {
		if !seen.insert(row.address.clone()) {
			plan.duplicates += 1;
		} else if match account {
			Some(account) => list.is_suppressed_for(account, &row.address),
			None => list.is_suppressed(&row.address),
		} {
			plan.already += 1;
		} else {
			plan.add.push(row);
		}
	}
	plan
}

/// Where `suppression import` reads and what it records.
pub(super) struct Import<'a> {
	pub file: &'a Path,
	pub account: Option<&'a str>,
	pub reason: Option<&'a str>,
	pub dry_run: bool,
	pub json: bool,
}

/// `suppression import FILE`.
pub(super) fn import(
	config: &Config,
	request: Import,
	now: u64,
	out: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	let default_reason = request.reason.unwrap_or(IMPORTED);
	if let Some(problem) = reason_problem(default_reason) {
		return Err(ResourceError::refused(problem));
	}
	let rows = parse(&read_input(request.file)?, now).map_err(|problems| {
		ResourceError::refused(format!(
			"the file was not imported:\n{}",
			problems.join("\n")
		))
	})?;
	let list = open(config)?;
	let plan = plan(&list, request.account, rows);
	let added = plan.add.len();
	if !request.dry_run {
		for row in &plan.add {
			let reason = row.reason.as_deref().unwrap_or(default_reason);
			let since = row.since.unwrap_or(now);
			match request.account {
				Some(account) => {
					list.try_suppress_for_because(account, &row.address, reason, since)
				}
				None => list.try_suppress_because(&row.address, reason, since),
			}
			.map_err(|error| {
				ResourceError::Failure(format!("cannot suppress {}: {error}", row.address))
			})?;
		}
	}
	let fields = json!({
		"account": request.account, "added": added,
		"already": plan.already, "duplicates": plan.duplicates,
	});
	if request.json {
		let mut object = super::super::json_out::change_object("import", added > 0, fields, None);
		if request.dry_run {
			object["result"] = "dry-run".into();
		}
		resource::json(out, &object).map_err(ResourceError::Failure)?;
	} else {
		let verb = if request.dry_run {
			"would add"
		} else {
			"added"
		};
		writeln!(
			out,
			"{verb} {added}, already suppressed {}, repeated in the file {}",
			plan.already, plan.duplicates
		)
		.map_err(failure)?;
	}
	Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
#[path = "suppression_exchange_tests.rs"]
mod tests;
