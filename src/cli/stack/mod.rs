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

use clap::Subcommand;

use crate::config::Config;

/// Path of the compose file `epistle init` writes, relative to
/// `data_dir`. Kept in one place so the operator-facing error names
/// the same path every command and the tests can rebuild it.
const COMPOSE_SUBDIR: &str = "compose";
const COMPOSE_FILE: &str = "compose.yaml";

/// The clap subcommand enum the dispatcher hands to [`run`]. The
/// shape mirrors the operator-facing verbs on the wire and is
/// translated one-to-one into the inner [`StackAction`] (kept
/// separate so the tests can build the action without clap).
#[derive(Debug, Subcommand)]
pub enum StackCli {
	/// Render compose.yaml again with this release, then recreate what changed.
	Update,
	/// Start the stack in the background.
	Up,
	/// Stop the stack.
	///
	/// The compose volumes are not removed: the database lives in one of them.
	Down,
	/// List the running services (table by default, JSON with
	/// `--json`).
	Ps {
		/// Re-serialise the parsed list as JSON instead of a table.
		#[arg(long)]
		json: bool,
	},
	/// Stream the service logs.
	Logs {
		/// Follow the log output as it is produced.
		#[arg(long)]
		follow: bool,
		/// Optional service name to filter on.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Restart the whole stack, or a single service.
	Restart {
		/// Optional service name to restart.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Stop the whole stack, or one service, without removing containers.
	///
	/// Stop the whole stack, or a single service (for example `mail` before a
	/// restore, keeping `db` up), without removing containers.
	Stop {
		/// Optional service name to stop.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Start what `stop` stopped.
	Start {
		/// Optional service name to start.
		#[arg(value_name = "SERVICE")]
		service: Option<String>,
	},
	/// Go back to the binary the last upgrade replaced; run as root.
	///
	/// When the new release already migrated the schema, the database dump
	/// `stack update` took before the restart is restored too. dpkg still
	/// records the newer version; see docs/cli.md for the limits.
	Rollback {
		/// The kept version to go back to; the newest one below this release
		/// by default.
		#[arg(long, value_name = "VERSION")]
		to: Option<String>,
		/// Do not ask for confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// The database half of `rollback`, run as the service account.
	#[command(hide = true)]
	RollbackDb,
	/// Turn the certificates container on or off (see
	/// docs/operations/container-split.md).
	#[command(hide = true)]
	Certs {
		/// `enable` or `disable`.
		#[command(subcommand)]
		action: CertsCli,
	},
	/// List each service's memory and process limits, or change one with `set`.
	Resources {
		/// Print JSON instead of a table.
		#[arg(long, global = true)]
		json: bool,
		/// `set <SERVICE> --memory <SIZE>`; without it the limits are listed.
		#[command(subcommand)]
		action: Option<resources::ResourcesCli>,
	},
}

pub use certs::CertsCli;

impl From<StackCli> for StackAction {
	fn from(value: StackCli) -> Self {
		match value {
			StackCli::Update => StackAction::Update,
			StackCli::Up => StackAction::Up,
			StackCli::Down => StackAction::Down,
			StackCli::Ps { json } => StackAction::Ps { as_json: json },
			StackCli::Logs { follow, service } => StackAction::Logs { follow, service },
			StackCli::Restart { service } => StackAction::Restart { service },
			StackCli::Stop { service } => StackAction::Passthrough {
				verb: "stop",
				service,
			},
			StackCli::Start { service } => StackAction::Passthrough {
				verb: "start",
				service,
			},
			StackCli::Rollback { .. } => StackAction::Rollback,
			StackCli::RollbackDb => StackAction::RollbackDb,
			StackCli::Certs { action } => action.action(),
			StackCli::Resources { json, action } => StackAction::Resources { action, json },
		}
	}
}

/// The stack subcommand the operator picked, with the operator's
/// `epistle` arguments already extracted by clap. The body here is a
/// straight `podup` wrapper, so each variant holds the trailing
/// arguments verbatim.
#[derive(Debug)]
pub(crate) enum StackAction {
	/// Render the compose file again, then recreate changed services and restart mail.
	Update,
	/// `podup -f <compose> up -d`, start the stack in the background.
	Up,
	/// `podup -f <compose> down`, stop the stack. Volumes are never
	/// removed (`-v`/`--volumes` are deliberately not exposed): the
	/// PostgreSQL data lives in a named volume and the operator must
	/// not lose it.
	Down,
	/// `podup -f <compose> ps --format json`, print the running
	/// services as a small table, or as JSON with `--json`.
	Ps {
		/// Re-serialise the parsed list as JSON instead of the table.
		as_json: bool,
	},
	/// `podup -f <compose> logs [--follow] [<service>]`, stream the
	/// logs, optionally following and optionally filtered to one
	/// service.
	Logs {
		/// Pass `--follow` to podup.
		follow: bool,
		/// Optional service name to filter on; passed as a positional.
		service: Option<String>,
	},
	/// `podup -f <compose> restart [<service>]`, restart the whole
	/// stack or one service.
	Restart {
		/// Optional service name to restart; passed as a positional.
		service: Option<String>,
	},
	/// `podup -f <compose> <verb> [<service>]` for `stop` and `start`.
	Passthrough {
		/// The podup subcommand.
		verb: &'static str,
		/// Optional service name; passed as a positional.
		service: Option<String>,
	},
	/// Dispatched as root before the stack is reached; here only to keep
	/// the conversion total.
	Rollback,
	/// Stop mail and restore the pre-update dump if the schema moved.
	RollbackDb,
	/// Turn the certificates container on or off.
	Certs {
		/// `true` to run it.
		on: bool,
	},
	/// Show or change the limits in the compose file; podup is not run.
	Resources {
		/// `set`, or `None` to list.
		action: Option<resources::ResourcesCli>,
		/// Print JSON.
		json: bool,
	},
	/// `podup -f <compose> up -d <service>`, recreate one service from
	/// the current compose file. A restart keeps the container as it was
	/// created, so a change to its published ports needs this.
	Recreate {
		/// The service to recreate.
		service: String,
	},
}

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
		StackAction::Certs { on } => certs::run(config, &compose, podup, on),
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
