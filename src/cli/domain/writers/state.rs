//! The commit of a change to the hosted-domain state file: the change goes
//! through [`crate::domain::state::edit`], the line and the records are
//! printed as before, and instead of restarting `mail` the command waits for
//! the running server to reload the file.

use std::io::Write;
use std::process::ExitCode;

use crate::cli::json_out::{Reload, change_object, dry_run_object};
use crate::config::Config;
use crate::domain::state::{Change, Committed, EditError, edit};

use super::{Commit, print_domain_records, record_lines};

/// How a change is run: a dry run prints the diff of the state file and
/// writes nothing; with `json` stdout gets one object.
#[derive(Debug, Clone, Copy)]
pub(in crate::cli::domain) struct Mode {
	pub dry_run: bool,
	pub json: bool,
}

fn io(error: std::io::Error) -> EditError {
	EditError::Io(error.to_string())
}

/// Commit `change` to the state file of `config`'s data directory and report
/// it the way the command always has. Returns what was committed, so a
/// caller can tell the operator more about it.
pub(in crate::cli::domain) fn commit_state(
	config: &Config,
	change: &Change,
	commit: Commit,
	mode: Mode,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<(ExitCode, Committed), EditError> {
	let Commit {
		subject,
		verb,
		already,
		action,
		mut fields,
		records_for,
	} = commit;
	if mode.dry_run {
		let preview = edit::preview(config, change)?;
		let diff = crate::cli::config_edit::unified_diff(
			&preview.path,
			&preview.before.render().map_err(io)?,
			&preview.after.render().map_err(io)?,
		);
		if mode.json {
			writeln!(out, "{}", dry_run_object(action, fields, diff)).map_err(io)?;
		} else {
			write!(out, "{diff}").map_err(io)?;
		}
		return Ok((ExitCode::SUCCESS, preview));
	}
	let committed = edit::commit(config, change)?;
	if !committed.changed {
		writeln!(status, "{subject} already {already}; nothing changed.").map_err(io)?;
		if mode.json {
			let object = change_object(action, false, fields, Some(Reload::None));
			writeln!(out, "{object}").map_err(io)?;
		}
		return Ok((ExitCode::SUCCESS, committed));
	}
	writeln!(status, "{subject} {verb}.").map_err(io)?;
	if let Some(domain) = records_for {
		if mode.json {
			fields["records"] = record_lines(&committed.config, domain).map_err(io)?.into();
		} else {
			print_domain_records(&committed.config, domain, out).map_err(io)?;
		}
	}
	let reload = Reload::from(crate::cli::account::reload::wait(&committed.path, status));
	if mode.json {
		let object = change_object(action, true, fields, Some(reload));
		writeln!(out, "{object}").map_err(io)?;
	}
	Ok((ExitCode::SUCCESS, committed))
}
