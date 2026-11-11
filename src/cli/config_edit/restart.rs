use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use super::Outcome;
use crate::cli::json_out::Reload;
use crate::cli::resource::ResourceError;
use crate::cli::{init, stack};
use crate::config::Config;

/// Set once at start-up by `--no-restart`.
static DEFER: AtomicBool = AtomicBool::new(false);

/// Make every change of this run leave the stack's services as they are.
pub(crate) fn defer_restarts(on: bool) {
	DEFER.store(on, Ordering::Relaxed);
}

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

/// Like [`after_ports_change_reporting`] for a change to the DNS credential:
/// the container that mounts it is recreated, `certs` when the stack runs
/// the certificates container and `mail` otherwise.
///
/// `also` names the services whose definition the change touched besides
/// that one: with the certificates container running, `mail` loses the
/// credential when it still carried it, and a container that keeps the
/// mount it had still has the token.
pub(crate) fn after_credential_change_reporting(
	config: &Config,
	outcome: Outcome,
	status: &mut impl Write,
	run: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
	also: &[&str],
) -> Result<(ExitCode, Reload), ResourceError> {
	let compose = init::compose_file_path(&config.data_dir);
	let service = match stack::certs::runs_certs(&compose) {
		Ok(true) => "certs",
		Ok(false) => "mail",
		Err(error) => return Err(ResourceError::from(error)),
	};
	let mut services = vec![service.to_string()];
	for one in also {
		if !services.iter().any(|have| have == one) {
			services.push((*one).to_string());
		}
	}
	let action = if services.len() == 1 {
		stack::StackAction::Recreate {
			service: services.remove(0),
		}
	} else {
		stack::StackAction::RecreateServices { services }
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
	apply_deferring(
		DEFER.load(Ordering::Relaxed),
		config,
		outcome,
		needs_restart,
		status,
		run,
		action,
	)
}

/// [`apply`] with `defer` given: the stack is left alone and the notice
/// says how to apply the change.
pub(super) fn apply_deferring(
	defer: bool,
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
		Ok(_) if defer => {
			writeln!(
				status,
				"Not restarted (--no-restart): the change takes effect at the next restart; run `epistle stack apply` to apply it."
			)
			.map_err(|error| ResourceError::Failure(error.to_string()))?;
			Ok((ExitCode::SUCCESS, Reload::Deferred))
		}
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
