//! Run database administration where the compose stack's socket is mounted.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command as ProcessCommand, ExitCode};
use std::str::FromStr;

use super::{Command, status::CheckArea};
use crate::config::Config;

fn database_config(command: &Command) -> Option<&Path> {
	match command {
		Command::Ban { config, .. }
		| Command::Learning { config, .. }
		| Command::Check {
			config,
			area: CheckArea::Db,
			..
		}
		| Command::Account {
			config,
			action: super::account::Subcommand::Remove { .. },
			..
		}
		| Command::Legacy(super::legacy::Legacy::AccountRemove { config, .. }) => Some(config),
		_ => None,
	}
}

/// `podup exec` of the mail container's epistle with `args`, when the
/// database socket only exists inside the stack; `None` when the database is
/// reachable from here (or there is no stack), so the caller runs locally.
pub(super) fn exec_spec(
	config: &Config,
	args: &[OsString],
) -> Result<Option<ProcessCommand>, String> {
	let Some(database) = &config.database else {
		return Ok(None);
	};
	if !super::init::compose_file_path(&config.data_dir).is_file() {
		return Ok(None);
	}
	let options = sqlx::postgres::PgConnectOptions::from_str(&database.url)
		.map_err(|_| "cannot parse the configured PostgreSQL URL".to_string())?;
	let Some(socket) = options.get_socket() else {
		return Ok(None);
	};
	stack_exec_for_socket(config, socket, args)
}

/// `podup exec` of the mail container's epistle with `args`, when clamd's
/// socket (`[antispam] clamd_socket`) only exists inside the stack; `None`
/// when it is reachable from here or clamd is not configured.
pub(super) fn clamd_exec_spec(
	config: &Config,
	args: &[OsString],
) -> Result<Option<ProcessCommand>, String> {
	match &config.antispam.clamd_socket {
		Some(socket) => stack_exec_for_socket(config, socket, args),
		None => Ok(None),
	}
}

/// The stack-side command for a Unix socket that does not exist on this
/// host but is mounted in the mail container; `None` when there is no
/// stack or the socket is reachable here.
fn stack_exec_for_socket(
	config: &Config,
	socket: &Path,
	args: &[OsString],
) -> Result<Option<ProcessCommand>, String> {
	let compose = super::init::compose_file_path(&config.data_dir);
	if !compose.is_file() || socket.exists() {
		return Ok(None);
	}

	// Read the path used by serve rather than repeating the compose mount layout.
	let bytes = std::fs::read(&compose).map_err(|error| format!("cannot read compose: {error}"))?;
	let document: serde_json::Value = serde_json::from_slice(&bytes)
		.map_err(|_| "cannot parse the generated compose file".to_string())?;
	let command = document["services"]["mail"]["command"]
		.as_array()
		.ok_or("the mail service has no command in the compose file")?;
	let config_path = command
		.windows(2)
		.find(|pair| pair[0].as_str() == Some("--config"))
		.and_then(|pair| pair[1].as_str())
		.ok_or("the mail command has no --config path in the compose file")?;
	let mut child = super::stack::build_command(
		"podup",
		&compose,
		&["exec", "-T", "mail", super::init::HOST_EPISTLE_PATH],
	);
	let mut args = args.iter();
	while let Some(arg) = args.next() {
		if arg == "--config" {
			args.next();
		} else if !arg.to_string_lossy().starts_with("--config=") {
			child.arg(arg);
		}
	}
	child.arg("--config").arg(config_path);
	Ok(Some(child))
}

fn require_running_mail(json: &str) -> Result<(), String> {
	let rows: Vec<serde_json::Value> =
		serde_json::from_str(json).map_err(|_| "cannot parse podup ps output".to_string())?;
	if rows
		.iter()
		.any(|row| row["Service"] == "mail" && row["State"] == "running")
	{
		Ok(())
	} else {
		Err("the mail container is not running; run `epistle stack up`".to_string())
	}
}

/// Fail early, with a hint, when the mail container is not running.
pub(super) fn ensure_mail_running(config: &Config) -> Result<(), String> {
	let compose = super::init::compose_file_path(&config.data_dir);
	let json =
		super::stack::started::ps_json_with("podup", &compose, super::stack::started::PS_TIMEOUT)?;
	require_running_mail(&json)
}

pub(super) fn reexecute(command: &Command) -> Result<Option<ExitCode>, String> {
	let Some(path) = database_config(command) else {
		return Ok(None);
	};
	let Ok(config) = Config::load(path) else {
		return Ok(None);
	};
	let args = super::pick::effective_args();
	let Some(mut child) = exec_spec(&config, &args)? else {
		return Ok(None);
	};
	ensure_mail_running(&config)?;
	let status = child
		.status()
		.map_err(|error| format!("cannot run podup: {error}"))?;
	Ok(Some(ExitCode::from(status.code().unwrap_or(1) as u8)))
}

#[cfg(test)]
#[path = "container_db_tests.rs"]
mod tests;
