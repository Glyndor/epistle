//! `epistle rotate`: the recovery procedure after a compromise.
//!
//! It walks the [registry] of every secret and credential. With
//! `--dry-run` it says, for each one, what epistle does and what stays with
//! the operator outside the server, and changes nothing. Without it, it
//! [rotates](mod@run) every secret this server can rotate and lists the rest.
//! `--accounts-only` runs the reset of the accounts' credentials alone.

mod accounts;
mod plan;
pub(super) mod registry;
mod run;

pub(super) use run::lock;

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

#[cfg(test)]
mod tests;

/// Print the plan, or run the rotation of the configuration at `config`.
pub(super) fn run(
	config: &Path,
	(all, accounts_only): (bool, bool),
	(dry_run, yes): (bool, bool),
	json: bool,
) -> ExitCode {
	if accounts_only && dry_run {
		return accounts::dry_run(config, json, &mut std::io::stdout().lock());
	}
	if (all || accounts_only) && !dry_run {
		let options = run::Options {
			yes,
			json,
			now: crate::cli::dkim::now_epoch(),
			scope: if accounts_only {
				run::Scope::Accounts
			} else {
				run::Scope::All
			},
		};
		return run::execute(
			config,
			options,
			&mut std::io::stdout().lock(),
			&mut crate::cli::style::stderr(),
			crate::cli::stack::run,
		);
	}
	execute(all, dry_run, json, &mut std::io::stdout().lock())
}

fn execute(all: bool, dry_run: bool, json: bool, out: &mut impl Write) -> ExitCode {
	if !all {
		eprintln!(
			"`epistle rotate` needs `--all` or `--accounts-only`; to rotate one kind of secret use \
			 its own command, which `epistle rotate --all --dry-run` lists"
		);
		return ExitCode::from(2);
	}
	debug_assert!(
		dry_run,
		"the run without --dry-run goes through run::execute"
	);
	let written = if json {
		plan::json(out)
	} else {
		plan::text(out)
	};
	match written {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			eprintln!("cannot write the plan: {error}");
			ExitCode::FAILURE
		}
	}
}
