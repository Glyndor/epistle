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
use std::process::ExitCode;

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
}

impl Reload {
	/// The value written to the `reload` field.
	pub(crate) fn name(self) -> &'static str {
		match self {
			Reload::Loaded => "loaded",
			Reload::NoServer => "no-server",
			Reload::TimedOut => "timed-out",
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
