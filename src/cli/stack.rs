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
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// The `podup` version this build requires at minimum. Mirrors the
/// `podup (>= 5.10.13)` dependency in `debian/control`; a test reads
/// the control file and asserts the two are equal so the floor cannot
/// drift away from the package relationship.
const PODUP_FLOOR: &str = "5.10.13";

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
	/// Pull images and recreate changed services, updating the default mail image.
	Update,
	/// Start the stack in the background.
	Up,
	/// Stop the stack. The compose volumes are not removed: the
	/// database lives in one of them.
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
}

impl From<StackCli> for StackAction {
	fn from(value: StackCli) -> Self {
		match value {
			StackCli::Update => StackAction::Update,
			StackCli::Up => StackAction::Up,
			StackCli::Down => StackAction::Down,
			StackCli::Ps { json } => StackAction::Ps { as_json: json },
			StackCli::Logs { follow, service } => StackAction::Logs { follow, service },
			StackCli::Restart { service } => StackAction::Restart { service },
		}
	}
}

/// The stack subcommand the operator picked, with the operator's
/// `epistle` arguments already extracted by clap. The body here is a
/// straight `podup` wrapper, so each variant holds the trailing
/// arguments verbatim.
#[derive(Debug)]
pub(super) enum StackAction {
	/// Refresh the default mail image, pull images, and recreate changed services.
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
	if let Err(error) = super::stack_socket::ensure() {
		super::style::error(error);
		return ExitCode::FAILURE;
	}
	let podup = match ensure_podup_floor() {
		Ok(()) => "podup",
		Err(code) => return code,
	};
	match action {
		StackAction::Update => {
			if let Err(error) = super::stack_update::rewrite_default_image(&compose) {
				super::style::error(format_args!("cannot update {}: {error}", compose.display()));
				return ExitCode::FAILURE;
			}
			run_sequence(podup, &compose, &[&["pull"], &["up", "-d"]])
		}
		StackAction::Up => {
			run_sequence(podup, &compose, &[&["up", "-d"], &["autostart", "install"]])
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
	}
}

/// Return the path of the compose file the operator's `data_dir`
/// carries. The shape is fixed by `epistle init` and the only thing
/// this build reads from disk, so the helper is the single source of
/// truth and the test for "missing compose file" can rebuild it.
fn compose_path(data_dir: &Path) -> PathBuf {
	data_dir.join(COMPOSE_SUBDIR).join(COMPOSE_FILE)
}

/// Spawn `podup --version`, parse the `vMAJOR.MINOR.PATCH` it prints,
/// and refuse to run any subcommand below [`PODUP_FLOOR`]. The error
/// names both the version the host has and the floor, so the operator
/// can tell at a glance which one is wrong. Returns `Ok(())` on
/// success, `Err(ExitCode::FAILURE)` on a missing binary, a parse
/// failure, or a too-old version.
fn ensure_podup_floor() -> Result<(), ExitCode> {
	let mut command = Command::new("podup");
	command.arg("--version");
	let output = match command.output() {
		Ok(output) => output,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			super::style::error(
				"`podup` is required by `epistle stack` but was not found on PATH; \
				 install it with `apt install podup` from apt.glyndor.net",
			);
			return Err(ExitCode::FAILURE);
		}
		Err(error) => {
			super::style::error(format_args!("cannot run `podup --version`: {error}"));
			return Err(ExitCode::FAILURE);
		}
	};
	if !output.status.success() {
		super::style::error(format_args!(
			"`podup --version` exited with status {}: the binary on PATH is not a usable podup",
			output.status
		));
		return Err(exit_code_from_status(&output.status));
	}
	let stdout = String::from_utf8_lossy(&output.stdout);
	// The real version is on the last non-empty line: podup prints
	// a leading blank before the banner, so `lines().last()` would
	// land on the trailing empty string and report an empty parse.
	let Some(line) = stdout.lines().rev().find(|line| !line.trim().is_empty()) else {
		super::style::error("`podup --version` produced no output");
		return Err(ExitCode::FAILURE);
	};
	let Some(version) = line
		.trim()
		.strip_prefix("podup version ")
		.and_then(|rest| rest.strip_prefix('v'))
		.unwrap_or(line.trim())
		.split_whitespace()
		.next()
	else {
		super::style::error(format_args!(
			"`podup --version` printed a line I cannot read: {line:?}"
		));
		return Err(ExitCode::FAILURE);
	};
	if version_at_least(version, PODUP_FLOOR) {
		Ok(())
	} else {
		super::style::error(format_args!(
			"`podup` {version} is older than the required floor {PODUP_FLOOR}; \
			 upgrade with `apt install podup` (>= {PODUP_FLOOR})"
		));
		Err(ExitCode::FAILURE)
	}
}

/// Compare two dotted version strings component by component.
/// Returns `true` when `candidate` is at least `floor`. The
/// comparison is numeric per component so `5.10.10` is greater than
/// `5.9.0`; a lexicographic compare would say the opposite.
fn version_at_least(candidate: &str, floor: &str) -> bool {
	let Ok(candidate) = parse_version(candidate) else {
		return false;
	};
	let Ok(floor) = parse_version(floor) else {
		return false;
	};
	candidate >= floor
}

fn parse_version(input: &str) -> Result<Vec<u64>, std::num::ParseIntError> {
	input.split('.').map(|part| part.parse::<u64>()).collect()
}

/// Spawn `podup` with the trailing arguments the subcommand chose,
/// inherit stdio so the operator sees the same `podup` output a bare
/// shell would have shown, and propagate the exit code. The one-line
/// error names the exact argv, so a `podup` failure points at the
/// command that produced it.
fn run_sequence(podup: &str, compose: &Path, steps: &[&[&str]]) -> ExitCode {
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
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.status()
	{
		Ok(status) => status,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			super::style::error(format_args!(
				"`podup` was on PATH for `--version` but is gone now: {error}"
			));
			return ExitCode::FAILURE;
		}
		Err(error) => {
			super::style::error(format_args!("cannot run `podup` for the stack: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if status.success() {
		ExitCode::SUCCESS
	} else {
		super::style::error(format_args!(
			"`podup -f {} {}` exited with status {status}",
			compose.display(),
			extra.join(" ")
		));
		exit_code_from_status(&status)
	}
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
fn build_command(podup: &str, compose: &Path, extra: &[&str]) -> Command {
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

/// One row in the JSON podup prints. Only the fields the table
/// renders are decoded; anything else is left in `extra` so a future
/// podup release that adds columns does not break the parser. The
/// `deny_unknown_fields` default is intentionally *not* set here.
#[derive(Debug, Deserialize, Serialize)]
struct PsEntry {
	/// Service name from the compose file.
	#[serde(rename = "Service")]
	service: String,
	/// Podman state string (`"running"`, `"exited"`, ...).
	#[serde(rename = "State")]
	state: String,
	/// Healthcheck status. `""` when the container has no healthcheck.
	#[serde(rename = "Health", default)]
	health: String,
	/// Last observed process exit code.
	#[serde(rename = "ExitCode")]
	exit_code: i64,
	/// Image the container was started from.
	#[serde(rename = "Image")]
	image: String,
	/// Published ports: one entry per `host:port -> target/proto`
	/// mapping. Empty for services that publish nothing.
	#[serde(rename = "Publishers", default)]
	publishers: Vec<Publisher>,
}

/// One published port mapping.
#[derive(Debug, Deserialize, Serialize)]
struct Publisher {
	/// `host:port` the operator connects to. Empty for
	/// `network_mode: host` mappings.
	#[serde(rename = "URL", default)]
	url: String,
	/// Port the process inside the container listens on.
	#[serde(rename = "TargetPort")]
	target_port: u16,
	/// Port the host actually binds (may differ from `URL` after
	/// `0:0` random allocation). podup 5.10.10 emits `null` when
	/// the port is exposed inside the container network but has no
	/// host binding; treating it as a plain `u16` would reject the
	/// whole service array, so the field is optional.
	#[serde(rename = "PublishedPort")]
	published_port: Option<u16>,
	/// Protocol: `tcp` or `udp`.
	#[serde(rename = "Protocol")]
	protocol: String,
}

/// Print the parsed `ps` rows as an aligned table to `out`. Three
/// columns: service, state, then `health (or -) / ports` so a
/// non-empty row stays one line. The "published ports" cell is the
/// one a human reaches for, so it gets a separate helper. A write
/// failure is returned so the caller can map it to a non-zero exit
/// (redirecting the table to a full disk must not pass silently).
fn print_table(entries: &[PsEntry], out: &mut impl std::io::Write) -> std::io::Result<()> {
	for entry in entries {
		let health = if entry.health.is_empty() {
			"-"
		} else {
			&entry.health
		};
		let ports = format_ports(&entry.publishers);
		writeln!(
			out,
			"{service}\t{state}\t{health}\t{ports}",
			service = entry.service,
			state = entry.state,
			health = health,
			ports = ports
		)?;
	}
	Ok(())
}

/// Render one cell's worth of published ports: every mapping becomes
/// `host:port->target/proto` and they are joined with a comma. A
/// mapping that podup reports without a host binding (the
/// `PublishedPort: null` case) drops the `host:port->` prefix and
/// renders as `target/proto` so the cell still carries the protocol
/// the operator needs to recognise the service. An empty list
/// renders as `-` so the table does not carry blank cells.
fn format_ports(publishers: &[Publisher]) -> String {
	if publishers.is_empty() {
		return "-".to_string();
	}
	let parts: Vec<String> = publishers
		.iter()
		.map(|p| match p.published_port {
			Some(published) => format!(
				"{host}:{published}->{target}/{proto}",
				host = p.url,
				published = published,
				target = p.target_port,
				proto = p.protocol
			),
			None => format!(
				"{target}/{proto}",
				target = p.target_port,
				proto = p.protocol
			),
		})
		.collect();
	parts.join(",")
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stack_tests_service.rs"]
mod tests_service;

#[cfg(test)]
#[path = "stack_tests_override.rs"]
mod tests_override;
