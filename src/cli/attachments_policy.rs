//! `epistle attachments policy show|set|unset`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use super::{PolicyCli, PolicyKey, print_json};
use crate::antispam::attachments::rules::ALWAYS_DANGEROUS;
use crate::cli::config_edit::{ConfigDocument, Outcome, after_change_with};
use crate::cli::resource::ResourceError;
use crate::cli::stack::StackAction;
use crate::config::{
	AttachmentMode, Attachments, Config, ContentAction, MAX_EXTENSION_LEN, MAX_EXTENSIONS,
	normalise_extension, valid_extension,
};

impl PolicyKey {
	/// The name on the command line.
	fn name(self) -> &'static str {
		match self {
			Self::Mode => "mode",
			Self::Macros => "macros",
			Self::EncryptedArchives => "encrypted-archives",
			Self::BlockExtensions => "block-extensions",
			Self::AllowExtensions => "allow-extensions",
		}
	}

	/// The key in `[attachments]`.
	fn field(self) -> &'static str {
		match self {
			Self::Mode => "mode",
			Self::Macros => "macros",
			Self::EncryptedArchives => "encrypted_archives",
			Self::BlockExtensions => "block_extensions",
			Self::AllowExtensions => "allow_extensions",
		}
	}
}

/// Run one policy action; `restart` restarts the stack after a change.
pub(super) fn execute(
	path: &Path,
	action: PolicyCli,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, ResourceError> {
	match action {
		PolicyCli::Show { json } => {
			let config =
				Config::load(path).map_err(|error| ResourceError::Failure(error.to_string()))?;
			show(&config.attachments, json, out)?;
			Ok(ExitCode::SUCCESS)
		}
		PolicyCli::Set { key, value, json } => {
			let mut document = ConfigDocument::open(path)?;
			apply_set(&mut document, key, &value)?;
			commit(document, key, "set", json, dry_run, out, status, restart)
		}
		PolicyCli::Unset { key, json } => {
			let mut document = ConfigDocument::open(path)?;
			document.remove_table_key(&["attachments"], key.field())?;
			commit(document, key, "unset", json, dry_run, out, status, restart)
		}
	}
}

fn apply_set(
	document: &mut ConfigDocument,
	key: PolicyKey,
	values: &[String],
) -> Result<(), ResourceError> {
	let name = key.name();
	match key {
		PolicyKey::BlockExtensions | PolicyKey::AllowExtensions => {
			// Refused before any per-value work, so the cost of a refusal does
			// not grow with what was typed.
			if values.len() > MAX_EXTENSIONS {
				return Err(ResourceError::refused(format!(
					"{name} takes at most {MAX_EXTENSIONS} extensions (received {})",
					values.len()
				)));
			}
			let mut list = toml_edit::Array::new();
			let mut seen = Vec::new();
			for value in values {
				if !valid_extension(value) {
					return Err(ResourceError::refused(format!(
						"{name}: {value:?} is not an extension (letters, digits, - and _, up to {MAX_EXTENSION_LEN})"
					)));
				}
				let extension = normalise_extension(value);
				if !seen.contains(&extension) {
					list.push(extension.as_str());
					seen.push(extension);
				}
			}
			document.set_table_key(&["attachments"], key.field(), list)?;
		}
		PolicyKey::Mode | PolicyKey::Macros | PolicyKey::EncryptedArchives => {
			let [value] = values else {
				return Err(ResourceError::refused(format!(
					"{name} takes exactly one value (received {})",
					values.len()
				)));
			};
			let value = value.trim().to_ascii_lowercase();
			let (accepted, expected): (&[&str], &str) = match key {
				PolicyKey::Mode => (
					&["off", "flag", "quarantine", "reject"],
					"off, flag, quarantine or reject",
				),
				_ => (
					&["allow", "flag", "quarantine"],
					"allow, flag or quarantine",
				),
			};
			if !accepted.contains(&value.as_str()) {
				return Err(ResourceError::refused(format!(
					"{name} expected {expected} (got {value:?})"
				)));
			}
			document.set_table_key(&["attachments"], key.field(), value)?;
		}
	}
	Ok(())
}

/// Write the change (or print it under `--dry-run`), then restart.
#[allow(clippy::too_many_arguments)]
fn commit(
	document: ConfigDocument,
	key: PolicyKey,
	verb: &str,
	json: bool,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, ResourceError> {
	let failed = |error: std::io::Error| ResourceError::Failure(error.to_string());
	if dry_run {
		write!(
			out,
			"{}",
			document.dry_run().map_err(ResourceError::Refusal)?
		)
		.map_err(failed)?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config().map_err(ResourceError::Refusal)?;
	let outcome = document.commit()?;
	if outcome == Outcome::Unchanged {
		writeln!(
			status,
			"attachments {} already set; nothing changed.",
			key.name()
		)
		.map_err(failed)?;
	} else {
		writeln!(status, "attachments {} {verb}.", key.name()).map_err(failed)?;
	}
	if json {
		show(&config.attachments, true, out)?;
	}
	after_change_with(&config, outcome, true, status, restart)
}

/// Print the policy in effect: one `key\tvalue` line per key, or one JSON
/// object.
fn show(section: &Attachments, json: bool, out: &mut impl Write) -> Result<(), ResourceError> {
	let list = |values: &[String]| -> Vec<String> {
		let mut normalised: Vec<String> = Vec::new();
		for value in values.iter().map(|value| normalise_extension(value)) {
			if !normalised.contains(&value) {
				normalised.push(value);
			}
		}
		normalised
	};
	let (block, allow) = (
		list(&section.block_extensions),
		list(&section.allow_extensions),
	);
	if json {
		return print_json(
			out,
			&serde_json::json!({
				"mode": mode_name(section.mode),
				"macros": action_name(section.macros),
				"encrypted-archives": action_name(section.encrypted_archives),
				"block-extensions": block,
				"allow-extensions": allow,
				"always-dangerous": ALWAYS_DANGEROUS,
			}),
		);
	}
	let joined = |values: &[String]| match values {
		[] => "(none)".to_string(),
		values => values.join(","),
	};
	write!(
		out,
		"mode\t{}\nmacros\t{}\nencrypted-archives\t{}\nblock-extensions\t{}\n\
		 allow-extensions\t{}\nalways-dangerous\t{}\n",
		mode_name(section.mode),
		action_name(section.macros),
		action_name(section.encrypted_archives),
		joined(&block),
		joined(&allow),
		ALWAYS_DANGEROUS.join(","),
	)
	.map_err(|error| ResourceError::Failure(error.to_string()))
}

/// The configuration value of `mode`.
pub(super) fn mode_name(mode: AttachmentMode) -> &'static str {
	match mode {
		AttachmentMode::Off => "off",
		AttachmentMode::Flag => "flag",
		AttachmentMode::Quarantine => "quarantine",
		AttachmentMode::Reject => "reject",
	}
}

fn action_name(action: ContentAction) -> &'static str {
	match action {
		ContentAction::Allow => "allow",
		ContentAction::Flag => "flag",
		ContentAction::Quarantine => "quarantine",
	}
}
