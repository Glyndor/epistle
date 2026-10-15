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
	let mut printed = Vec::new();
	let code = backup::run_restore(
		&config,
		&input,
		force,
		dry_run,
		&mut printed,
		&mut style::stderr(),
	);
	if code != ExitCode::SUCCESS {
		return code;
	}
	crate::cli::json_out::print(
		&mut std::io::stdout().lock(),
		&restore_json(&printed, dry_run),
	)
}

/// The `--json` result of a restore, from the summary `run_restore`
/// printed: `would restore N entries:` and one indented line per entry
/// for a dry run, `restored N entries` otherwise.
fn restore_json(printed: &[u8], dry_run: bool) -> serde_json::Value {
	let text = String::from_utf8_lossy(printed);
	let mut lines = text.lines();
	let entries: u64 = lines
		.next()
		.and_then(|first| first.split_whitespace().find_map(|word| word.parse().ok()))
		.unwrap_or(0);
	if !dry_run {
		return serde_json::json!({ "result": "saved", "action": "restore", "entries": entries });
	}
	let paths: Vec<&str> = lines
		.filter(|line| line.starts_with("  "))
		.map(str::trim)
		.collect();
	serde_json::json!({
		"result": "dry-run", "action": "restore", "entries": entries, "paths": paths,
	})
}
