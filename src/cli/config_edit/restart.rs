use std::io::Write;
use std::process::ExitCode;

use super::Outcome;
use crate::cli::json_out::Reload;
use crate::cli::resource::ResourceError;
use crate::cli::{init, stack};
use crate::config::Config;

/// Restart the stack mail service after a change through `restart`, or
/// report that a manual restart is needed.
pub(crate) fn after_change_with(
	config: &Config,
	outcome: Outcome,
	needs_restart: bool,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
) -> Result<ExitCode, ResourceError> {
	after_change_reporting(config, outcome, needs_restart, status, restart).map(|(code, _)| code)
}

/// [`after_change_with`], also saying how the change reached the server
/// for a `--json` result.
pub(crate) fn after_change_reporting(
	config: &Config,
	outcome: Outcome,
	needs_restart: bool,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
) -> Result<(ExitCode, Reload), ResourceError> {
	let action = stack::StackAction::Restart {
		service: Some("mail".into()),
	};
	apply(config, outcome, needs_restart, status, restart, action)
}

/// Like [`after_change_with`] for a change to the published ports: a restart
/// keeps the container's old port forwarding, so mail is recreated from the
/// updated compose file. Also says how the change reached the server.
pub(crate) fn after_ports_change_reporting(
	config: &Config,
	outcome: Outcome,
	status: &mut impl Write,
	run: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
) -> Result<(ExitCode, Reload), ResourceError> {
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
) -> Result<(ExitCode, Reload), ResourceError> {
	if outcome == Outcome::Unchanged || !needs_restart {
		return Ok((ExitCode::SUCCESS, Reload::None));
	}
	let compose = init::compose_file_path(&config.data_dir);
	match std::fs::metadata(&compose) {
		Ok(_) => {
			let code = run(config, action);
			let reload = if code == ExitCode::SUCCESS {
				Reload::Restarted
			} else {
				Reload::RestartFailed
			};
			Ok((code, reload))
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			writeln!(status, "The server must be restarted.")
				.map_err(|error| ResourceError::Failure(error.to_string()))?;
			Ok((ExitCode::SUCCESS, Reload::RestartNeeded))
		}
		Err(error) => Err(ResourceError::Failure(format!(
			"cannot stat {}: {error}",
			compose.display()
		))),
	}
}
