//! `epistle rotate`: the recovery procedure after a compromise.
//!
//! It walks the [registry](registry) of every secret and credential and says,
//! for each one, what epistle does and what stays with the operator outside
//! the server. Today only `--dry-run` exists: the listing changes nothing, so
//! an operator can read the whole procedure before the bad hour.

mod plan;
pub(super) mod registry;

use std::io::Write;
use std::process::ExitCode;

#[cfg(test)]
mod tests;

/// Print the plan to stdout, or refuse a combination that is not built yet.
pub(super) fn run(all: bool, dry_run: bool, json: bool) -> ExitCode {
	execute(all, dry_run, json, &mut std::io::stdout().lock())
}

fn execute(all: bool, dry_run: bool, json: bool, out: &mut impl Write) -> ExitCode {
	if !all {
		eprintln!(
			"`epistle rotate` needs `--all`; to rotate one kind of secret use its own command, \
			 which `epistle rotate --all --dry-run` lists"
		);
		return ExitCode::from(2);
	}
	if !dry_run {
		eprintln!(
			"only `--dry-run` exists so far: it lists every secret and what would be done, and \
			 changes nothing. The run that changes them is tracked in {}",
			registry::issue_url(registry::TRACKING_ISSUE)
		);
		return ExitCode::from(3);
	}
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
