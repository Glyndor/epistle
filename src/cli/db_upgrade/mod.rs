//! `epistle db upgrade`: move the stack's PostgreSQL to the major this
//! release pins, with a dump and a restore instead of an image swap.

use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;

use crate::config::Config;

mod flow;
mod host;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

pub(super) use host::{query, query_within};

/// The `epistle db` actions.
#[derive(Debug, Subcommand)]
pub enum DbCli {
	/// Move the stack's PostgreSQL to the major this release pins.
	///
	/// Dumps the database, starts the new major beside the old cluster,
	/// restores into it and compares the row count of every table. Any
	/// failure puts the old major back. The old cluster stays in the volume.
	Upgrade,
	/// Show the version, size and connections of the stack's PostgreSQL.
	///
	/// Runs one read-only query in the database container and changes
	/// nothing. Exits 3 when the configuration has no `[database]` or there
	/// is no stack to ask.
	Status,
}

/// Run an `epistle db` action.
/// Run the database action. With `json` the steps stay on stderr and a
/// success prints `{"result": "done", "action": "upgrade", "postgres"}`.
/// `path` is where the configuration lives, and the upgrade takes the common
/// configuration lock on it: the flow reads the generated file, stops the
/// stack, dumps, and writes the file back minutes later, and a service edit
/// made in between would be lost.
pub(super) fn run(config: &Config, path: &Path, action: DbCli, json: bool) -> ExitCode {
	match action {
		DbCli::Status => super::db_status::run(config, json),
		DbCli::Upgrade => {
			let _held = match super::service::lock::acquire(path) {
				Ok(held) => held,
				Err(error) => {
					super::style::error(format_args!("cannot upgrade the database: {error}"));
					return ExitCode::FAILURE;
				}
			};
			let mut stack = match host::Podup::new(config) {
				Ok(stack) => stack,
				Err(error) => {
					super::style::error(format_args!("cannot upgrade the database: {error}"));
					return ExitCode::FAILURE;
				}
			};
			let target = crate::cli::init::images::postgres();
			match flow::upgrade(&mut stack, target) {
				Ok(()) if json => {
					let result = serde_json::json!({
						"result": "done", "action": "upgrade", "postgres": target,
					});
					super::json_out::print(&mut std::io::stdout().lock(), &result)
				}
				Ok(()) => ExitCode::SUCCESS,
				Err(error) => {
					super::style::error(format_args!("database upgrade failed: {error}"));
					ExitCode::FAILURE
				}
			}
		}
	}
}
