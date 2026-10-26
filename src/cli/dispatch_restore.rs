//! `epistle restore`: confirm, read the archive from stdin, replay it.
//! Kept out of `dispatch.rs` so the dispatch table stays under the
//! per-file line budget.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::cli::{backup, style};
use crate::config::Config;

/// Run the `restore` subcommand: read the archive from stdin, load the
/// config, hand the bytes to [`backup::run_restore`]. Lives here rather
/// than in the match arm so the dispatch table stays compact and the
/// per-file line budget keeps `dispatch.rs` under 500 code lines.
pub(in crate::cli) fn dispatch_restore(
	config: PathBuf,
	(force, dry_run, yes): (bool, bool, bool),
	json: bool,
) -> ExitCode {
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
		&& let Err(code) =
			crate::cli::prompt::confirm_destructive_on_terminal("restore", &question, yes)
	{
		return code;
	}
	let mut input = Vec::new();
	if let Err(error) = std::io::Read::read_to_end(&mut crate::cli::prompt::stdin(), &mut input) {
		style::error(format_args!("reading archive from stdin: {error}"));
		return ExitCode::FAILURE;
	}
	if !json {
		return backup::run_restore(
			&config,
			&input,
			force,
			dry_run,
			&mut std::io::stdout().lock(),
			&mut style::stderr(),
		);
	}
	let (code, summary) = backup::run_restore_reporting(
		&config,
		&input,
		force,
		dry_run,
		&mut std::io::sink(),
		&mut style::stderr(),
	);
	if code != ExitCode::SUCCESS {
		return code;
	}
	crate::cli::json_out::print(
		&mut std::io::stdout().lock(),
		&restore_json(&summary, dry_run),
	)
}

/// The `--json` result of a restore: the entry count and, for a dry run,
/// the destination of each entry, as the restore itself counted them.
fn restore_json(summary: &backup::RestoreSummary, dry_run: bool) -> serde_json::Value {
	if !dry_run {
		return serde_json::json!({
			"result": "saved", "action": "restore", "entries": summary.entries,
		});
	}
	serde_json::json!({
		"result": "dry-run", "action": "restore", "entries": summary.entries,
		"paths": summary.paths,
	})
}

#[cfg(test)]
#[path = "dispatch_restore_tests.rs"]
mod tests;
