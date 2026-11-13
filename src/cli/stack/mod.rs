//! `epistle stack`: drive the `podup` command-line against the compose
//! file `epistle init` writes under `<data_dir>/compose/compose.yaml`.
//!
//! Every subcommand is a thin wrapper that builds the exact `podup`
//! argv, hands the child the inherited stdio for streaming commands
//! (`up`, `down`, `logs`, `restart`) and a captured stdout for the data
//! command (`ps`). `podup`'s own exit code becomes the exit code, with
//! a one-line error to stderr when it is non-zero. Nothing in this
//! module shells out through `/bin/sh`; the binary is invoked through
//! `std::process::Command` so argv cannot be reinterpreted by a shell.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::config::Config;

/// Path of the compose file `epistle init` writes, relative to
/// `data_dir`. Kept in one place so the operator-facing error names
/// the same path every command and the tests can rebuild it.
const COMPOSE_SUBDIR: &str = "compose";
const COMPOSE_FILE: &str = "compose.yaml";

mod action;
pub(crate) use action::StackAction;
pub use action::StackCli;

pub(super) mod certs;
pub(super) mod dumps;
pub(super) mod health;
mod images;
pub(super) mod port_warnings;
pub(super) mod resources;
mod retry;
pub(super) mod rollback;
mod socket;
pub(super) mod started;
mod update;

mod entry;
pub(super) use entry::run_from_path;

mod podup_floor;
mod table;
use podup_floor::ensure_podup_floor;
#[cfg(test)]
use podup_floor::{PODUP_FLOOR, parse_version, version_at_least};
use table::{PsEntry, print_table};
#[cfg(test)]
use table::{Publisher, format_ports};

/// Run the `stack` subcommand the operator typed. With `json`, podup's
/// own output has gone to stderr and a success prints one object naming
/// the verb and the service: `{"result": "done", "action", "service"}`.
/// `ps` and `resources` print their own JSON, and `logs` streams raw lines,
/// so it refuses `--json`.
pub(super) fn run_reporting(config: &Config, cli: StackCli, json: bool) -> ExitCode {
	let (verb, service) = match &cli {
		StackCli::Logs { .. } if json => {
			return super::exit::refused(
				"stack logs streams the services' raw log lines; it has no --json form",
			);
		}
		StackCli::Ps { json: leaf } => {
			let as_json = *leaf || json;
			return run(config, StackAction::Ps { as_json });
		}
		StackCli::Update => ("update", None),
		StackCli::Up => ("up", None),
		StackCli::Apply => ("apply", None),
		StackCli::Down => ("down", None),
		StackCli::Restart { service } => ("restart", service.clone()),
		StackCli::Stop { service } => ("stop", service.clone()),
		StackCli::Start { service } => ("start", service.clone()),
		// These print their own output (or none), so no object follows.
		StackCli::Logs { .. }
		| StackCli::Resources { .. }
		| StackCli::Rollback { .. }
		| StackCli::RollbackDb
		| StackCli::Certs { .. } => return run(config, cli.into()),
	};
	let code = run(config, cli.into());
	if !json || code != ExitCode::SUCCESS {
		return code;
	}
	let mut out = std::io::stdout().lock();
	let result = serde_json::json!({ "result": "done", "action": verb, "service": service });
	super::json_out::print(&mut out, &result)
}

/// Run the `stack` subcommand. The config is loaded here only to read
/// `data_dir`; the compose file is read with `metadata` to refuse
/// early if `epistle init` has not been run, so the error names the
/// exact path the operator needs to create.
pub(super) fn run(config: &Config, action: StackAction) -> ExitCode {
	let compose = compose_path(&config.data_dir);
	match std::fs::metadata(&compose) {
		Ok(_) => {}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			super::style::error(format_args!(
				"{} does not exist; run `epistle init` with `services.database` stated to write it",
				compose.display()
			));
			return ExitCode::FAILURE;
		}
		Err(error) => {
			super::style::error(format_args!("cannot stat {}: {error}", compose.display()));
			return ExitCode::FAILURE;
		}
	}
	// The limits live in the compose file alone: no podup, no socket.
	let action = match action {
		StackAction::Resources { action, json } => {
			return resources::run(
				&compose,
				crate::smtp::memory_fit::largest_message(config.max_message_size),
				action,
				json,
				&mut std::io::stdout(),
			);
		}
		action => action,
	};
	if let Err(error) = socket::ensure() {
		super::style::error(error);
		return ExitCode::FAILURE;
	}
	let podup = match ensure_podup_floor() {
		Ok(()) => "podup",
		Err(code) => return code,
	};
	match action {
		StackAction::Update => update::run(config, &compose, podup),
		StackAction::Rollback => {
			super::style::error("run it as root: sudo epistle stack rollback");
			ExitCode::FAILURE
		}
		StackAction::RollbackDb => rollback::restore_db(config, &compose, podup),
		StackAction::Certs { on, yes } => certs::run(config, &compose, podup, on, yes),
		StackAction::Up => {
			// The ports the stack publishes on every interface on purpose
			// are the ones podup warns about on every run; the warning is
			// replaced by one note, and the warning about a port nobody
			// asked to publish stays as podup printed it.
			let mut published = port_warnings::Published::new(config);
			let code = certs::up(&config.data_dir, &compose, podup, &mut published);
			let mut out = std::io::stderr().lock();
			published.note(&mut out);
			code
		}
		StackAction::Apply => run_sequence(podup, &compose, &[&["up", "-d"], &["restart", "mail"]]),
		StackAction::Down => {
			run_sequence(podup, &compose, &[&["autostart", "uninstall"], &["down"]])
		}
		StackAction::Ps { as_json } => {
			let json = match capture_podup(podup, &compose, &["ps", "--format", "json"]) {
				Ok(out) => out,
				Err(code) => return code,
			};
			let parsed: Vec<PsEntry> = match serde_json::from_str(&json) {
				Ok(entries) => entries,
				Err(error) => {
					super::style::error(format_args!(
						"podup -f {} ps --format json produced output that is not a JSON array of services: {error}",
						compose.display()
					));
					return ExitCode::FAILURE;
				}
			};
			let mut out = std::io::stdout().lock();
			if as_json {
				match serde_json::to_string_pretty(&parsed) {
					Ok(serialised) => match writeln!(out, "{serialised}") {
						Ok(()) => ExitCode::SUCCESS,
						Err(error) => {
							super::style::error(format_args!("cannot write ps output: {error}"));
							ExitCode::FAILURE
						}
					},
					Err(error) => {
						super::style::error(format_args!("cannot serialise ps output: {error}"));
						ExitCode::FAILURE
					}
				}
			} else {
				match print_table(&parsed, &mut out) {
					Ok(()) => ExitCode::SUCCESS,
					Err(error) => {
						super::style::error(format_args!("cannot write ps output: {error}"));
						ExitCode::FAILURE
					}
				}
			}
		}
		StackAction::Logs { follow, service } => {
			let mut extra: Vec<String> = Vec::new();
			extra.push("logs".to_string());
			if follow {
				extra.push("--follow".to_string());
			}
			if let Some(name) = service {
				extra.push(name);
			}
			let extra_ref: Vec<&str> = extra.iter().map(String::as_str).collect();
			run_inherited(podup, &compose, &extra_ref)
		}
		StackAction::Restart { service } => {
			let mut extra: Vec<String> = Vec::new();
			extra.push("restart".to_string());
			if let Some(name) = service {
				extra.push(name);
			}
			let extra_ref: Vec<&str> = extra.iter().map(String::as_str).collect();
			run_inherited(podup, &compose, &extra_ref)
		}
		StackAction::Passthrough { verb, service } => {
			let mut extra: Vec<&str> = vec![verb];
			if let Some(name) = service.as_deref() {
				extra.push(name);
			}
			run_inherited(podup, &compose, &extra)
		}
		StackAction::Recreate { service } => {
			run_inherited(podup, &compose, &["up", "-d", &service])
		}
		StackAction::RecreateServices { services } => {
			// One `podup up -d <service>` for each: every one of them
			// recreates exactly its own container, and the first that
			// fails stops the rest.
			let mut code = ExitCode::SUCCESS;
			for service in &services {
				code = run_inherited(podup, &compose, &["up", "-d", service]);
				if code != ExitCode::SUCCESS {
					break;
				}
			}
			code
		}
		StackAction::Resources { action, json } => resources::run(
			&compose,
			crate::smtp::memory_fit::largest_message(config.max_message_size),
			action,
			json,
			&mut std::io::stdout(),
		),
	}
}

/// Return the path of the compose file the operator's `data_dir`
/// carries. The shape is fixed by `epistle init` and the only thing
/// this build reads from disk, so the helper is the single source of
/// truth and the test for "missing compose file" can rebuild it.
pub(super) fn compose_path(data_dir: &Path) -> PathBuf {
	data_dir.join(COMPOSE_SUBDIR).join(COMPOSE_FILE)
}

/// Spawn `podup` with the trailing arguments the subcommand chose,
/// inherit stdio so the operator sees the same `podup` output a bare
/// shell would have shown, and propagate the exit code. The one-line
/// error names the exact argv, so a `podup` failure points at the
/// command that produced it.
pub(super) fn run_sequence(podup: &str, compose: &Path, steps: &[&[&str]]) -> ExitCode {
	for step in steps {
		let code = run_inherited(podup, compose, step);
		if code != ExitCode::SUCCESS {
			return code;
		}
	}
	ExitCode::SUCCESS
}

fn run_inherited(podup: &str, compose: &Path, extra: &[&str]) -> ExitCode {
	let status = match build_command(podup, compose, extra)
		.stdin(Stdio::inherit())
		.stdout(super::json_out::child_stdout())
		.stderr(Stdio::inherit())
		.status()
	{
		Ok(status) => status,
		Err(error) => return not_started(error),
	};
	finished(&status, compose, extra)
}

/// The exit code a finished `podup` leaves behind: its own, with the
/// one-line error a non-zero status gets. The error names the exact
/// argv, so a `podup` failure points at the command that produced it.
pub(super) fn finished(
	status: &std::process::ExitStatus,
	compose: &Path,
	extra: &[&str],
) -> ExitCode {
	if status.success() {
		ExitCode::SUCCESS
	} else {
		super::style::error(format_args!(
			"`podup -f {} {}` exited with status {status}",
			compose.display(),
			extra.join(" ")
		));
		exit_code_from_status(status)
	}
}

/// The exit code a `podup` that could not be started leaves behind: the
/// one-line error names what went wrong.
pub(super) fn not_started(error: std::io::Error) -> ExitCode {
	if error.kind() == std::io::ErrorKind::NotFound {
		super::style::error(format_args!(
			"`podup` was on PATH for `--version` but is gone now: {error}"
		));
	} else {
		super::style::error(format_args!("cannot run `podup` for the stack: {error}"));
	}
	ExitCode::FAILURE
}

/// Spawn `podup` and capture its stdout: the data command (`ps`)
/// needs the bytes for parsing, and the caller turns the bytes into
/// the table or the JSON document the operator asked for. The exit
/// code is propagated the same way as the inherited path.
fn capture_podup(podup: &str, compose: &Path, extra: &[&str]) -> Result<String, ExitCode> {
	let output = build_command(podup, compose, extra)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::inherit())
		.output()
		.map_err(|error| {
			super::style::error(format_args!("cannot run `podup` for the stack: {error}"));
			ExitCode::FAILURE
		})?;
	if !output.status.success() {
		super::style::error(format_args!(
			"`podup -f {} {}` exited with status {}",
			compose.display(),
			extra.join(" "),
			output.status
		));
		return Err(exit_code_from_status(&output.status));
	}
	Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Convert a `std::process::ExitStatus` into an `ExitCode`, carrying
/// the underlying podup code through so a `podup` failure surfaces
/// as the same number on the `epistle` side. A signal termination
/// (no exit code, like SIGTERM) becomes `ExitCode::FAILURE`; a
/// success stays `ExitCode::SUCCESS`.
fn exit_code_from_status(status: &std::process::ExitStatus) -> ExitCode {
	match status.code() {
		Some(code) => ExitCode::from(code as u8),
		None => ExitCode::FAILURE,
	}
}

/// The argv every subcommand starts from. Kept in one place so a
/// future change to the compose-file flag (today `-f`) is a single
/// edit, and the tests that pin the argv can rebuild it.
pub(super) fn build_command(podup: &str, compose: &Path, extra: &[&str]) -> Command {
	let mut command = Command::new(podup);
	command.arg("-f").arg(compose);
	let override_path = compose.with_file_name("compose.override.yaml");
	if override_path.exists() {
		command.arg("-f").arg(override_path);
	}
	for piece in extra {
		command.arg(piece);
	}
	command
}

#[cfg(test)]
mod tests;
