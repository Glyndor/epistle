//! Shared plumbing for commands that edit one resource in the configuration.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use super::config_edit::{Companion, ConfigDocument, Outcome, after_change_reporting};
use super::stack::StackAction;
use crate::config::Config;

/// The error a resource command can return to its driver. Distinguishes
/// a refusal (exit code 2, "fix the command": an unknown name, an
/// invalid argument, a destructive action without `--yes`) from an
/// operation failure (exit code 1, "retry later": a file that could
/// not be read, the database unreachable).
#[derive(Debug)]
pub(crate) enum ResourceError {
	/// A usage error: the command refused with a message the operator
	/// can act on without a retry.
	Refusal(String),
	/// An I/O or parse-layer failure: the command should be retried
	/// once the underlying problem clears.
	Failure(String),
}

impl From<String> for ResourceError {
	fn from(value: String) -> Self {
		ResourceError::Failure(value)
	}
}

impl From<&str> for ResourceError {
	fn from(value: &str) -> Self {
		ResourceError::Failure(value.to_string())
	}
}

impl std::fmt::Display for ResourceError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ResourceError::Refusal(message) | ResourceError::Failure(message) => {
				formatter.write_str(message)
			}
		}
	}
}

impl AsRef<str> for ResourceError {
	fn as_ref(&self) -> &str {
		match self {
			ResourceError::Refusal(message) | ResourceError::Failure(message) => message,
		}
	}
}

impl PartialEq<&str> for ResourceError {
	fn eq(&self, other: &&str) -> bool {
		self.as_ref() == *other
	}
}

impl PartialEq<str> for ResourceError {
	fn eq(&self, other: &str) -> bool {
		self.as_ref() == other
	}
}

impl PartialEq<String> for ResourceError {
	fn eq(&self, other: &String) -> bool {
		self.as_ref() == other.as_str()
	}
}

impl ResourceError {
	/// Build a refusal from any message; the call site keeps the
	/// message and the exit-code mapping in one place.
	pub(crate) fn refused(message: impl Into<String>) -> Self {
		ResourceError::Refusal(message.into())
	}
}

/// Print the error and map a typed `ResourceError` result to an exit
/// code: a refusal exits 2, an operation failure exits 1.
pub(super) fn exit_resource(result: Result<ExitCode, ResourceError>) -> ExitCode {
	match result {
		Ok(code) => code,
		Err(error) => {
			let message = match &error {
				ResourceError::Refusal(message) | ResourceError::Failure(message) => {
					message.clone()
				}
			};
			super::style::error(message);
			match error {
				ResourceError::Refusal(_) => ExitCode::from(super::exit::REFUSED),
				ResourceError::Failure(_) => ExitCode::FAILURE,
			}
		}
	}
}

/// What a configuration edit reports: `label` names the resource in the
/// status line ("relay saved"); with `json` the result goes to stdout as
/// one object with `action` and the keys of `fields`.
pub(super) struct Edit<'a> {
	/// The resource name in the status line.
	pub label: &'a str,
	/// The `action` of the JSON result.
	pub action: &'a str,
	/// The keys that name what changed, an object.
	pub fields: serde_json::Value,
	/// Print the result as JSON.
	pub json: bool,
}

/// Print a dry-run diff, or validate, write and apply the restart policy.
/// With `--json` a dry run prints `{"result": "dry-run", ..., "diff"}` and
/// a commit prints the change object with its `reload`.
pub(super) fn finish(
	document: ConfigDocument,
	dry_run: bool,
	edit: Edit,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, ResourceError> {
	if dry_run {
		return preview(&document, None, &edit, out);
	}
	let failure = |error: std::io::Error| ResourceError::Failure(error.to_string());
	let config = document.config()?;
	let outcome = document.commit()?;
	let changed = outcome == Outcome::Changed;
	let state = if changed { "saved" } else { "unchanged" };
	writeln!(status, "{} {state}", edit.label).map_err(failure)?;
	let (code, reload) = after_change_reporting(&config, outcome, true, status, restart)?;
	if edit.json {
		let object =
			super::json_out::change_object(edit.action, changed, edit.fields, Some(reload));
		writeln!(out, "{object}").map_err(failure)?;
	}
	Ok(code)
}

/// A change to a file beside the configuration: the file the transaction
/// would write, and the lines that say what changes in it.
pub(super) struct CompanionChange<'a> {
	/// The file that would be written.
	pub(super) companion: &'a Companion,
	/// The lines that say what changes in it.
	pub(super) lines: &'a [String],
}

/// Print the dry-run diff of the configuration and of the file that carries
/// the change into the container. The companion is a file a command stages
/// beside the configuration; a preview that leaves it out hides the change
/// the command is about to make.
pub(super) fn preview(
	document: &ConfigDocument,
	companion: Option<CompanionChange<'_>>,
	edit: &Edit,
	out: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	let failure = |error: std::io::Error| ResourceError::Failure(error.to_string());
	let diff = document.dry_run()?;
	if edit.json {
		let mut object = super::json_out::dry_run_object(edit.action, edit.fields.clone(), diff);
		if let Some(change) = companion {
			object["compose"] = serde_json::json!({
				"file": change.companion.path,
				"changes": change.lines,
			});
		}
		writeln!(out, "{object}").map_err(failure)?;
	} else {
		write!(out, "{diff}").map_err(failure)?;
		if let Some(change) = companion {
			for line in change.lines {
				writeln!(out, "{line}").map_err(failure)?;
			}
		}
	}
	Ok(ExitCode::SUCCESS)
}

/// A configuration edit chosen by a command, applied once the file is open.
pub(super) type Change = Box<dyn FnOnce(&mut ConfigDocument, &Config) -> Result<(), ResourceError>>;

/// Open the configuration, let `change` edit it, then validate and commit.
pub(super) fn apply_edit(
	path: &Path,
	dry_run: bool,
	edit: Edit,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
	change: impl FnOnce(&mut ConfigDocument, &Config) -> Result<(), ResourceError>,
) -> Result<ExitCode, ResourceError> {
	let mut document = ConfigDocument::open(path).map_err(ResourceError::Failure)?;
	let current = document.config().map_err(ResourceError::Failure)?;
	change(&mut document, &current)?;
	finish(document, dry_run, edit, out, status, restart)
}

/// Validate a DNS name taken from a flag and return it trimmed and lowercase.
/// The error names the flag and drops the loader's generic prefix.
pub(super) fn dns_name(flag: &str, value: &str) -> Result<String, String> {
	crate::config::validate_dns_name(flag, value).map_err(|error| {
		let text = error.to_string();
		text.strip_prefix("invalid configuration: ")
			.unwrap_or(&text)
			.to_string()
	})?;
	Ok(value.trim().to_ascii_lowercase())
}

/// Read one secret line without its line ending: with echo off when stdin is
/// a terminal, as one piped line otherwise. The value is checked for things
/// the configuration cannot store safely.
pub(super) fn read_secret(input: &mut dyn BufRead, what: &str) -> Result<String, String> {
	use super::prompt::Secret;
	let value = match super::prompt::secret_line(what, input) {
		Secret::Read(value) => value,
		Secret::Eof => return Err(format!("no {what} on stdin: pipe it in as one line")),
		Secret::Blank | Secret::Mismatch => return Err(format!("the {what} on stdin is empty")),
		Secret::Failed(error) => return Err(format!("cannot read the {what} from stdin: {error}")),
	};
	if value.trim().is_empty() {
		return Err(format!("the {what} on stdin is empty"));
	}
	if value.contains("${") {
		return Err(format!(
			"the {what} contains \"${{\", which the configuration loader would expand as an environment reference"
		));
	}
	if value.chars().any(char::is_control) {
		return Err(format!("the {what} contains control characters"));
	}
	Ok(value)
}

/// Write a JSON value followed by a newline.
pub(super) fn json(out: &mut impl Write, value: &impl serde::Serialize) -> Result<(), String> {
	serde_json::to_writer(&mut *out, value).map_err(|error| error.to_string())?;
	writeln!(out).map_err(|error| error.to_string())
}

/// A temporary configuration with a header comment, for command tests.
#[cfg(test)]
pub(super) fn test_config(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir_in(".").unwrap();
	let file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	std::fs::write(
		file.path(),
		format!(
			"# deployment\nhostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n\n# public socket\n[[listeners]]\nkind = 'smtp'\naddr = '0.0.0.0'\n{extra}",
			dir.path().canonicalize().unwrap()
		),
	)
	.unwrap();
	(dir, file)
}

/// The observable result of one command run in a test.
#[cfg(test)]
pub(super) struct Run {
	pub result: Result<ExitCode, ResourceError>,
	pub out: String,
	pub status: String,
	pub before: String,
	pub after: String,
}
