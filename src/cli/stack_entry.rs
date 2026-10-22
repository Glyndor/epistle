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
	match Config::load(path) {
		Ok(config) => run_reporting(&config, cli, json),
		Err(error) => {
			crate::cli::style::error(error);
			ExitCode::FAILURE
		}
	}
}
