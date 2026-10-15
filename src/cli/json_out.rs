//! One writer for the `--json` output of every command.
//!
//! A `list` prints a JSON array and a `show` prints a JSON object, each on
//! one line of stdout, so a script can pipe it into `jq` without caring
//! which resource produced it. A command that changes something prints one
//! result object built by [`Report::change`]: `result` (`saved` when it
//! wrote, `unchanged` when there was nothing to do), `action`, the fields
//! that name what changed, and `reload` when the command waits for the
//! running server. Diagnostics never go here: they stay on stderr through
//! `style`.

use std::io::Write;
use std::process::{ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

/// Write `value` as one line of JSON to `out`. A failed write (a closed
/// pipe, a full disk) is an operation failure, exit code 1.
pub(super) fn print(out: &mut impl Write, value: &Value) -> ExitCode {
	match writeln!(out, "{value}") {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			super::style::error(format_args!("writing JSON: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// How the running server picked up a change, the `reload` field of a
/// result object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reload {
	/// The server reported that it loaded the write.
	Loaded,
	/// No server was running, so there was nothing to wait for.
	NoServer,
	/// The server is running and had not loaded the write in time; it
	/// will on its next poll.
	TimedOut,
	/// The stack's mail service was restarted to apply the change.
	Restarted,
	/// The restart of the stack's mail service failed; the exit code is
	/// the restart's.
	RestartFailed,
	/// There is no stack to restart: the operator restarts the server.
	RestartNeeded,
	/// Nothing to apply: the change was empty or takes effect without a
	/// restart.
	None,
}

impl Reload {
	/// The value written to the `reload` field.
	pub(crate) fn name(self) -> &'static str {
		match self {
			Reload::Loaded => "loaded",
			Reload::NoServer => "no-server",
			Reload::TimedOut => "timed-out",
			Reload::Restarted => "restarted",
			Reload::RestartFailed => "restart-failed",
			Reload::RestartNeeded => "restart-needed",
			Reload::None => "none",
		}
	}
}

impl From<super::account_reload::Waited> for Reload {
	fn from(waited: super::account_reload::Waited) -> Self {
		use super::account_reload::Waited;
		match waited {
			Waited::Loaded => Reload::Loaded,
			Waited::NoServer => Reload::NoServer,
			Waited::TimedOut => Reload::TimedOut,
		}
	}
}

/// Where a command reports its result: a human line on stdout, or with
/// `--json` one JSON object on stdout and no human line.
pub(crate) struct Report<'a> {
	out: &'a mut dyn Write,
	json: bool,
}

impl<'a> Report<'a> {
	/// A report writing to `out`, as JSON when `json` is set.
	pub(crate) fn new(out: &'a mut dyn Write, json: bool) -> Self {
		Report { out, json }
	}

	/// Print the human confirmation `text`. With `--json` the result
	/// object replaces it, so nothing is printed.
	pub(crate) fn line(&mut self, text: impl std::fmt::Display) {
		if !self.json {
			let _ = writeln!(self.out, "{text}");
		}
	}

	/// Print `value` as the JSON result. Without `--json` nothing is
	/// printed and the exit code is success.
	pub(crate) fn object(&mut self, value: Value) -> ExitCode {
		if !self.json {
			return ExitCode::SUCCESS;
		}
		match writeln!(self.out, "{value}") {
			Ok(()) => ExitCode::SUCCESS,
			Err(error) => {
				super::style::error(format_args!("writing JSON: {error}"));
				ExitCode::FAILURE
			}
		}
	}

	/// Print the result of a change: `result` and `action`, then every
	/// key of `fields` (an object), then `reload` when the command waited
	/// for the server.
	pub(crate) fn change(
		&mut self,
		action: &str,
		changed: bool,
		fields: Value,
		reload: Option<Reload>,
	) -> ExitCode {
		self.object(change_object(action, changed, fields, reload))
	}
}

/// The result object of a change; see [`Report::change`].
pub(crate) fn change_object(
	action: &str,
	changed: bool,
	fields: Value,
	reload: Option<Reload>,
) -> Value {
	let mut object = serde_json::Map::new();
	object.insert(
		"result".into(),
		Value::from(if changed { "saved" } else { "unchanged" }),
	);
	object.insert("action".into(), Value::from(action));
	if let Value::Object(fields) = fields {
		object.extend(fields);
	}
	if let Some(reload) = reload {
		object.insert("reload".into(), Value::from(reload.name()));
	}
	Value::Object(object)
}

/// Set once the parsed command line asked for `--json`.
static STDOUT_RESERVED: AtomicBool = AtomicBool::new(false);

/// Reserve stdout for the JSON result when any command on the parsed
/// line carries `--json`: from then on a child process (podup,
/// systemctl) writes its own stdout to stderr, so stdout stays one JSON
/// document. The walk follows the one subcommand chain clap matched.
pub(crate) fn reserve_stdout_if_json(matches: &clap::ArgMatches) {
	let mut level = Some(matches);
	while let Some(current) = level {
		if let Ok(Some(true)) = current.try_get_one::<bool>("json") {
			STDOUT_RESERVED.store(true, Ordering::Relaxed);
			return;
		}
		level = current.subcommand().map(|(_, sub)| sub);
	}
}

/// The stdout a child process gets: the inherited one, or with stdout
/// reserved a copy of stderr. When stderr cannot be copied the child's
/// stdout is discarded rather than allowed onto the JSON stream.
pub(crate) fn child_stdout() -> Stdio {
	if !STDOUT_RESERVED.load(Ordering::Relaxed) {
		return Stdio::inherit();
	}
	use std::os::fd::AsFd;
	match std::io::stderr().as_fd().try_clone_to_owned() {
		Ok(fd) => Stdio::from(fd),
		Err(_) => Stdio::null(),
	}
}

/// With `--json`, the `ok\t<check>` lines a test command printed into
/// `printed` become one object: `{"result": "passed", "action", "checks"}`.
/// Only a passing test gets here; a failing one has printed its error on
/// stderr and left stdout empty.
pub(crate) fn passed(out: &mut impl Write, action: &str, printed: &[u8]) -> std::io::Result<()> {
	let checks: Vec<&str> = std::str::from_utf8(printed)
		.unwrap_or_default()
		.lines()
		.map(|line| line.strip_prefix("ok\t").unwrap_or(line))
		.collect();
	let value = serde_json::json!({ "result": "passed", "action": action, "checks": checks });
	writeln!(out, "{value}")
}

/// The `--json` result of a `--dry-run`: the change object with `result`
/// `dry-run` and the diff that was not written.
pub(crate) fn dry_run_object(action: &str, fields: Value, diff: String) -> Value {
	let mut object = change_object(action, false, fields, None);
	object["result"] = "dry-run".into();
	object["diff"] = diff.into();
	object
}
