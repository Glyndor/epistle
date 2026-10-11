use std::io::Write;
use std::process::ExitCode;

use super::Outcome;
use crate::cli::{init, stack};
use crate::config::Config;

/// Restart the stack mail service after a change, or report a manual restart.
pub fn after_change(
	config: &Config,
	outcome: Outcome,
	needs_restart: bool,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	after_change_with(config, outcome, needs_restart, status, stack::run)
}

pub(in crate::cli) fn after_change_with(
	config: &Config,
	outcome: Outcome,
	needs_restart: bool,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
) -> Result<ExitCode, String> {
	if outcome == Outcome::Unchanged || !needs_restart {
		return Ok(ExitCode::SUCCESS);
	}
	let compose = init::compose_file_path(&config.data_dir);
	match std::fs::metadata(&compose) {
		Ok(_) => Ok(restart(
			config,
			stack::StackAction::Restart {
				service: Some("mail".into()),
			},
		)),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			writeln!(status, "The server must be restarted.").map_err(|error| error.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		Err(error) => Err(format!("cannot stat {}: {error}", compose.display())),
	}
}
