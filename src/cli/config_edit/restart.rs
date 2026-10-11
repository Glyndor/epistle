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
	let action = stack::StackAction::Restart {
		service: Some("mail".into()),
	};
	apply(config, outcome, needs_restart, status, restart, action)
}

/// Like [`after_change_with`] for a change to the published ports: a restart
/// keeps the container's old port forwarding, so mail is recreated from the
/// updated compose file.
pub(in crate::cli) fn after_ports_change_with(
	config: &Config,
	outcome: Outcome,
	status: &mut impl Write,
	run: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
) -> Result<ExitCode, String> {
	let action = stack::StackAction::Recreate {
		service: "mail".into(),
	};
	apply(config, outcome, true, status, run, action)
}

fn apply(
	config: &Config,
	outcome: Outcome,
	needs_restart: bool,
	status: &mut impl Write,
	run: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
	action: stack::StackAction,
) -> Result<ExitCode, String> {
	if outcome == Outcome::Unchanged || !needs_restart {
		return Ok(ExitCode::SUCCESS);
	}
	let compose = init::compose_file_path(&config.data_dir);
	match std::fs::metadata(&compose) {
		Ok(_) => Ok(run(config, action)),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			writeln!(status, "The server must be restarted.").map_err(|error| error.to_string())?;
			Ok(ExitCode::SUCCESS)
		}
		Err(error) => Err(format!("cannot stat {}: {error}", compose.display())),
	}
}
