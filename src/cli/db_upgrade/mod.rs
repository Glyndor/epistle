//! `epistle db upgrade`: move the stack's PostgreSQL to the major this
//! release pins, with a dump and a restore instead of an image swap.

use std::process::ExitCode;

use clap::Subcommand;

use crate::config::Config;

mod flow;
mod host;

pub(super) use host::query;

/// The `epistle db` actions.
#[derive(Debug, Subcommand)]
pub enum DbCli {
	/// Move the stack's PostgreSQL to the major this release pins.
	///
	/// Dumps the database, starts the new major beside the old cluster,
	/// restores into it and compares the row count of every table. Any
	/// failure puts the old major back. The old cluster stays in the volume.
	Upgrade,
}

/// Run an `epistle db` action.
pub(super) fn run(config: &Config, action: DbCli) -> ExitCode {
	match action {
		DbCli::Upgrade => {
			let mut stack = match host::Podup::new(config) {
				Ok(stack) => stack,
				Err(error) => {
					super::style::error(format_args!("cannot upgrade the database: {error}"));
					return ExitCode::FAILURE;
				}
			};
			match flow::upgrade(&mut stack, crate::cli::init::images::postgres()) {
				Ok(summary) => {
					eprintln!("epistle: {summary}");
					ExitCode::SUCCESS
				}
				Err(error) => {
					super::style::error(format_args!("database upgrade failed: {error}"));
					ExitCode::FAILURE
				}
			}
		}
	}
}
