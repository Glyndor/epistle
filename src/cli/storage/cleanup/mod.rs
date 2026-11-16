//! `epistle storage cleanup`: list what the hourly cleanup would remove now.
//!
//! It never removes anything. The server removes, once an hour, and only on a
//! clock its time reference believes; this command has no such reference, so
//! it judges by the clock of the machine it runs on and says so.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use crate::config::Config;
use crate::imap::cleanup::{Mode, Policy, run as run_cleanup};

/// Print what the cleanup `[storage.cleanup]` describes would remove today.
pub(in crate::cli) fn run(
	path: &Path,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> ExitCode {
	let config = match Config::load(path) {
		Ok(config) => config,
		Err(error) => return fail(status, error),
	};
	let Some(policy) = Policy::from_config(&config) else {
		let _ = writeln!(
			status,
			"There is no [storage.cleanup] in the configuration, so nothing is removed."
		);
		return if json {
			crate::cli::json_out::print(out, &json!({ "messages": 0, "folders": [] }))
		} else {
			ExitCode::SUCCESS
		};
	};
	let retention = config
		.storage
		.as_ref()
		.map_or(0, |storage| storage.deleted_retention_days);
	let now = crate::storage::delivery_log::now_epoch();
	let report = match run_cleanup(&config.data_dir, &policy, retention, now, Mode::DryRun) {
		Ok(report) => report,
		Err(error) => return fail(status, error),
	};
	let _ = writeln!(
		status,
		"Judged by this machine's clock. The server removes only on a clock it believes."
	);
	if json {
		let folders: Vec<_> = report
			.folders
			.iter()
			.map(|folder| {
				json!({
					"account": folder.account,
					"folder": folder.folder,
					"days": folder.days,
					"messages": folder.messages,
				})
			})
			.collect();
		return crate::cli::json_out::print(
			out,
			&json!({ "messages": report.messages(), "folders": folders }),
		);
	}
	for folder in &report.folders {
		let line = format!(
			"{}\t{}\t{}\t{}",
			crate::cli::term::sanitize(&folder.account),
			crate::cli::term::sanitize(&folder.folder),
			folder.days,
			folder.messages
		);
		if writeln!(out, "{line}").is_err() {
			return ExitCode::FAILURE;
		}
	}
	let _ = writeln!(status, "{} message(s) would be removed.", report.messages());
	ExitCode::SUCCESS
}

fn fail(status: &mut impl Write, error: impl std::fmt::Display) -> ExitCode {
	let _ = writeln!(status, "{error}");
	ExitCode::FAILURE
}

#[cfg(test)]
mod tests;
