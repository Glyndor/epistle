//! The commit of a change to the alias state file: the change goes through
//! [`crate::aliases::edit`], the line is printed as before, and instead of
//! restarting `mail` the command waits for the running server to reload the
//! file, the way `epistle domain` does.

use std::io::Write;
use std::process::ExitCode;

use crate::aliases::{AliasError, Change, Origin, edit};
use crate::cli::json_out::{Reload, change_object, dry_run_object};
use crate::config::Config;

/// How a change is run: a dry run prints the diff of the state file and
/// writes nothing; with `json` stdout gets one object.
#[derive(Debug, Clone, Copy)]
pub(super) struct Mode {
	pub dry_run: bool,
	pub json: bool,
}

fn io(error: std::io::Error) -> AliasError {
	AliasError::Io(error.to_string())
}

/// Commit `change` for the operator and report it the way the command always
/// has: `alias ADDRESS VERB.` on the status stream, one JSON object on
/// `out` with `json`, the diff of the state file for a dry run.
pub(super) fn commit_state(
	config: &Config,
	change: &Change,
	verb: &str,
	mode: Mode,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, AliasError> {
	let address = change.address().to_string();
	let action = verb.replace("added", "add").replace("removed", "remove");
	let fields = serde_json::json!({ "alias": address });
	if mode.dry_run {
		let preview = edit::preview(config, change, &Origin::Operator)?;
		let diff = crate::cli::config_edit::unified_diff(
			&preview.path,
			&preview.before.render().map_err(io)?,
			&preview.after.render().map_err(io)?,
		);
		if mode.json {
			writeln!(out, "{}", dry_run_object(&action, fields, diff)).map_err(io)?;
		} else {
			write!(out, "{diff}").map_err(io)?;
		}
		return Ok(ExitCode::SUCCESS);
	}
	let committed = edit::commit(config, change, &Origin::Operator)?;
	if !committed.changed {
		writeln!(status, "alias {address} already {verb}; nothing changed.").map_err(io)?;
		if mode.json {
			let object = change_object(&action, false, fields, Some(Reload::None));
			writeln!(out, "{object}").map_err(io)?;
		}
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(status, "alias {address} {verb}.").map_err(io)?;
	let reload = Reload::from(crate::cli::account::reload::wait(&committed.path, status));
	if mode.json {
		let object = change_object(&action, true, fields, Some(reload));
		writeln!(out, "{object}").map_err(io)?;
	}
	Ok(ExitCode::SUCCESS)
}
