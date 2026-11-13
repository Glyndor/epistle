//! `epistle panel`: what the operator needs to know about the web panel.
//!
//! Today that is the admin id, the `{id}` of the panel's admin area
//! (`/app/{id}`), which `init` and `stack update` generate once per
//! installation. It is the one place the id is printed on purpose: the other
//! commands, their `--json` output, the status report and the logs never carry
//! it.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;
use serde_json::json;

use crate::cli::resource::{self, ResourceError};
use crate::config::Config;

#[cfg(test)]
mod tests;

/// Panel actions.
#[derive(Debug, Subcommand)]
pub enum PanelCli {
	/// Show the admin id: the address of the panel's admin area.
	///
	/// Prints the id on stdout and the path `/app/<id>` on stderr, to append
	/// to the address the panel is served at. The id is not a cryptographic
	/// secret, the session and the admin role are the barrier, but it is not
	/// public either: do not post it, link it from a public page or put it in
	/// a log or a ticket.
	AdminId {
		/// Print the id and the path as one JSON object on stdout.
		#[arg(long)]
		json: bool,
	},
}

pub(in crate::cli) fn run(path: &Path, action: PanelCli, json: bool) -> ExitCode {
	resource::exit_resource(load(path).and_then(|config| {
		execute_with(
			&config.data_dir,
			action,
			json,
			&mut std::io::stdout().lock(),
			&mut crate::cli::style::stderr(),
		)
	}))
}

fn load(path: &Path) -> Result<Config, ResourceError> {
	Config::load(path).map_err(|error| ResourceError::Failure(error.to_string()))
}

fn execute_with(
	data_dir: &Path,
	action: PanelCli,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	let PanelCli::AdminId { json: leaf } = action;
	let id = crate::cli::init::panel_admin_id(data_dir)
		.map_err(|error| ResourceError::Failure(error.to_string()))?
		.ok_or_else(|| {
			ResourceError::refused(
				"the panel has no admin id yet: it is created by `epistle init` or \
				 `epistle stack update` when the epistle-panel package is installed",
			)
		})?;
	let path = format!("/app/{id}");
	if leaf || json {
		resource::json(out, &json!({ "admin_id": id, "path": path }))?;
	} else {
		writeln!(out, "{id}").map_err(|error| error.to_string())?;
		writeln!(
			status,
			"admin area: {path}\n\
			 not a cryptographic secret, but do not publish it: keep it out of public \
			 pages, logs and tickets"
		)
		.map_err(|error| error.to_string())?;
	}
	Ok(ExitCode::SUCCESS)
}
