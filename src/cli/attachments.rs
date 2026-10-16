//! `epistle attachments`: show and edit the `[attachments]` policy, and
//! check what it would do with a message file without delivering it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};

use super::resource::ResourceError;
use super::style;

/// The attachments actions.
#[derive(Debug, Subcommand)]
pub enum AttachmentsCli {
	/// Show or edit the `[attachments]` policy.
	Policy {
		/// Policy action.
		#[command(subcommand)]
		action: PolicyCli,
	},
	/// Show what the policy would do with a message file.
	///
	/// Every attachment with its names, declared and real types and
	/// reasons, then the verdict. Nothing is delivered.
	Check {
		/// The message, as an `.eml` file.
		#[arg(value_name = "FILE")]
		file: PathBuf,
		/// Print one JSON object instead of text.
		#[arg(long)]
		json: bool,
		/// Exit with 1 when the verdict is quarantine or reject.
		#[arg(long)]
		strict: bool,
	},
}

/// The policy actions.
#[derive(Debug, Subcommand)]
pub enum PolicyCli {
	/// Print every policy key and its value in effect.
	Show {
		/// Print one JSON object keyed by policy key.
		#[arg(long)]
		json: bool,
	},
	/// Set one key; for the extension lists the values replace the list.
	Set {
		/// The policy key.
		#[arg(value_enum)]
		key: PolicyKey,
		/// The new value, or the extensions for a list key.
		#[arg(required = true)]
		value: Vec<String>,
	},
	/// Remove one key, restoring its default.
	Unset {
		/// The policy key.
		#[arg(value_enum)]
		key: PolicyKey,
	},
}

/// The `[attachments]` keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PolicyKey {
	/// `off`, `flag`, `quarantine` or `reject` (`mode`).
	Mode,
	/// `allow`, `flag` or `quarantine` for Office macros (`macros`).
	Macros,
	/// `allow`, `flag` or `quarantine` for encrypted archives
	/// (`encrypted_archives`).
	EncryptedArchives,
	/// Extensions treated as dangerous on top of the built-in list
	/// (`block_extensions`).
	BlockExtensions,
	/// Extensions removed from the dangerous list (`allow_extensions`).
	AllowExtensions,
}

/// Run one attachments action against the configuration at `path`.
pub(super) fn run(path: &Path, action: AttachmentsCli, dry_run: bool, json: bool) -> ExitCode {
	let mut out = std::io::stdout().lock();
	let result = match action {
		AttachmentsCli::Policy { action } => policy::execute(
			path,
			action,
			(dry_run, json),
			&mut out,
			&mut style::stderr(),
			super::stack::run,
		),
		AttachmentsCli::Check {
			file,
			json: leaf,
			strict,
		} => check::execute(path, &file, leaf || json, strict, &mut out),
	};
	match result {
		Ok(code) => code,
		Err(ResourceError::Refusal(message)) => super::exit::refused(message),
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

/// Write `value` as one line of JSON with every non-ASCII character
/// escaped (`\u202e`), so file names from a message can neither drive the
/// terminal nor reorder what it shows, and still parse back exactly.
fn print_json(
	out: &mut impl std::io::Write,
	value: &serde_json::Value,
) -> Result<(), ResourceError> {
	let mut line = String::new();
	for c in value.to_string().chars() {
		if c.is_ascii() {
			line.push(c);
		} else {
			for unit in c.encode_utf16(&mut [0; 2]) {
				line.push_str(&format!("\\u{unit:04x}"));
			}
		}
	}
	writeln!(out, "{line}").map_err(|error| ResourceError::Failure(error.to_string()))
}

#[path = "attachments_check.rs"]
mod check;
#[path = "attachments_policy.rs"]
mod policy;

#[cfg(test)]
#[path = "attachments_tests_check.rs"]
mod tests_check;
#[cfg(test)]
#[path = "attachments_tests_check_read.rs"]
mod tests_check_read;
#[cfg(test)]
#[path = "attachments_tests_check_strict.rs"]
mod tests_check_strict;
#[cfg(test)]
#[path = "attachments_tests_check_submission.rs"]
mod tests_check_submission;
#[cfg(test)]
#[path = "attachments_tests_policy.rs"]
mod tests_policy;
