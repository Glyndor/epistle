//! Load stack configuration while holding the shared writer lock.

use super::{Config, StackCli, run_reporting};
use std::path::Path;
use std::process::ExitCode;

/// Hold the shared writer lock before loading the configuration for a stack
/// update or a resource edit. Reloads called by service edits already hold it.
pub(in crate::cli) fn run_from_path(path: &Path, cli: StackCli, json: bool) -> ExitCode {
	let writes = matches!(
		cli,
		StackCli::Update
			| StackCli::Resources {
				action: Some(_),
				..
			}
	);
	let _held = if writes {
		match crate::cli::service_lock::acquire(path) {
			Ok(held) => Some(held),
			Err(error) => {
				crate::cli::style::error(error);
				return ExitCode::FAILURE;
			}
		}
	} else {
		None
	};
	match load(path) {
		Ok(config) => run_reporting(&config, cli, json),
		Err(error) => {
			crate::cli::style::error(error);
			ExitCode::FAILURE
		}
	}
}

/// The configuration as the loader reads it, from a read that never waits.
/// The common lock is already held, so a fifo at the path, or behind a
/// symlink, has to be refused by name instead of parking the command on a
/// writer that may never come, with every other writer of the directory kept
/// out behind it.
fn load(path: &Path) -> Result<Config, String> {
	let text = crate::cli::config_edit::read_through_link(path)?;
	Config::parse_text(&text, path).map_err(|error| error.to_string())
}
