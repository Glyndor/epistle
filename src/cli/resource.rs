//! Shared plumbing for commands that edit one resource in the configuration.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use super::config_edit::{ConfigDocument, Outcome, after_change_with};
use super::stack::StackAction;
use crate::config::Config;

/// Print the error and map a command result to an exit code.
pub(super) fn exit(result: Result<ExitCode, String>) -> ExitCode {
	match result {
		Ok(code) => code,
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}

/// Print a dry-run diff, or validate, write and apply the restart policy.
/// `label` names the resource in the status line ("relay saved").
pub(super) fn finish(
	document: ConfigDocument,
	dry_run: bool,
	label: &str,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, String> {
	if dry_run {
		write!(out, "{}", document.dry_run()?).map_err(|error| error.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	let state = if outcome == Outcome::Changed {
		"saved"
	} else {
		"unchanged"
	};
	writeln!(status, "{label} {state}").map_err(|error| error.to_string())?;
	after_change_with(&config, outcome, true, status, restart)
}

/// A configuration edit chosen by a command, applied once the file is open.
pub(super) type Change = Box<dyn FnOnce(&mut ConfigDocument, &Config) -> Result<(), String>>;

/// Open the configuration, let `change` edit it, then validate and commit.
pub(super) fn apply_edit(
	path: &Path,
	dry_run: bool,
	label: &str,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
	change: impl FnOnce(&mut ConfigDocument, &Config) -> Result<(), String>,
) -> Result<ExitCode, String> {
	let mut document = ConfigDocument::open(path)?;
	let current = document.config()?;
	change(&mut document, &current)?;
	finish(document, dry_run, label, out, status, restart)
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

/// Read one secret line without its line ending. The value is checked for
/// things the configuration cannot store safely, and is never echoed.
pub(super) fn read_secret(input: &mut dyn BufRead, what: &str) -> Result<String, String> {
	let mut line = String::new();
	let read = input
		.read_line(&mut line)
		.map_err(|error| format!("cannot read the {what} from stdin: {error}"))?;
	if read == 0 {
		return Err(format!("no {what} on stdin: pipe it in as one line"));
	}
	let value = line.trim_end_matches(['\n', '\r']);
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
	Ok(value.to_string())
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
