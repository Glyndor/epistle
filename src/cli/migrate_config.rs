//! `epistle migrate mox` and `epistle migrate stalwart`: show the import
//! plan, or apply it, and say what is left to do by hand.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use crate::migrate::import::Plan;
use crate::migrate::import::apply::{self, ApplyError, Outcome, Passwords};

/// Arguments shared by the configuration imports.
#[derive(Debug, Args)]
pub struct ImportArgs {
	/// Write each new account's temporary password to this new file (mode
	/// 0600) as `account<TAB>password` lines.
	#[arg(
		long,
		value_name = "FILE",
		conflicts_with = "password_reset",
		required_unless_present_any = ["password_reset", "dry_run"]
	)]
	pub passwords_out: Option<PathBuf>,
	/// Give new accounts a password nobody knows; set real ones later with
	/// `epistle account password`.
	#[arg(long)]
	pub password_reset: bool,
	/// Keep domains, accounts and aliases that already exist and add the
	/// rest, instead of refusing.
	#[arg(long)]
	pub merge: bool,
	/// Print the plan and the changes; write nothing.
	#[arg(long)]
	pub dry_run: bool,
	/// Print the plan and the changes as one JSON object on stdout.
	#[arg(long)]
	pub json: bool,
}

/// Run an import of `plan` into the configuration at `config`, restarting
/// the mail service afterwards when the stack runs.
pub(super) fn run(config: &Path, plan: Result<Plan, String>, args: &ImportArgs) -> ExitCode {
	let mut out = std::io::stdout().lock();
	let (code, changed) = import(config, plan, args, &mut out);
	if !changed {
		return code;
	}
	let restarted = crate::config::Config::load(config)
		.map_err(|error| crate::cli::resource::ResourceError::Failure(error.to_string()))
		.and_then(|config| {
			crate::cli::config_edit::after_change_with(
				&config,
				crate::cli::config_edit::Outcome::Changed,
				true,
				&mut crate::cli::style::stderr(),
				crate::cli::stack::run,
			)
		});
	match restarted {
		Ok(_) => code,
		Err(error) => {
			crate::cli::style::error(error.to_string());
			ExitCode::FAILURE
		}
	}
}

/// The import without the restart: the exit code, and whether the
/// configuration file changed.
pub(super) fn import(
	config: &Path,
	plan: Result<Plan, String>,
	args: &ImportArgs,
	out: &mut impl Write,
) -> (ExitCode, bool) {
	let plan = match plan {
		Ok(plan) => plan,
		Err(error) => return (crate::cli::exit::refused(error), false),
	};
	let prepared = match apply::prepare(&plan, config, args.merge) {
		Ok(prepared) => prepared,
		Err(error) => return (failed(&error), false),
	};
	if args.dry_run {
		print(out, &plan, &prepared.outcome, args, None);
		return (ExitCode::SUCCESS, false);
	}
	let passwords = match &args.passwords_out {
		Some(path) => Passwords::File(path.clone()),
		None => Passwords::Reset,
	};
	match apply::apply(&plan, prepared, &passwords) {
		Ok(outcome) => {
			print(out, &plan, &outcome, args, Some(&passwords));
			(ExitCode::SUCCESS, outcome.config_changed)
		}
		Err(error) => (failed(&error), false),
	}
}

fn failed(error: &ApplyError) -> ExitCode {
	match error {
		ApplyError::Refused(message) => crate::cli::exit::refused(message),
		ApplyError::Failed(message) => {
			crate::cli::style::error(message);
			ExitCode::FAILURE
		}
	}
}

fn print(
	out: &mut impl Write,
	plan: &Plan,
	outcome: &Outcome,
	args: &ImportArgs,
	passwords: Option<&Passwords>,
) {
	if args.json {
		let value = serde_json::json!({
			"dry_run": args.dry_run,
			"plan": plan,
			"changes": outcome,
		});
		let _ = crate::cli::json_out::print(out, &value);
		return;
	}
	let _ = writeln!(out, "source: {}", plan.source);
	let list = |items: &[String]| {
		if items.is_empty() {
			"none".to_string()
		} else {
			items.join(", ")
		}
	};
	let verb = if args.dry_run { "would add" } else { "added" };
	let _ = writeln!(out, "domains {verb}: {}", list(&outcome.domains_added));
	let _ = writeln!(out, "accounts {verb}: {}", list(&outcome.accounts_added));
	let _ = writeln!(out, "aliases {verb}: {}", list(&outcome.aliases_added));
	for (what, kept) in [
		("domains", &outcome.domains_kept),
		("accounts", &outcome.accounts_kept),
		("aliases", &outcome.aliases_kept),
	] {
		if !kept.is_empty() {
			let _ = writeln!(
				out,
				"{what} already here, kept as they are: {}",
				kept.join(", ")
			);
		}
	}
	for key in &plan.keys {
		let _ = writeln!(
			out,
			"dkim key: {} selector {} ({})",
			key.domain,
			key.selector,
			serde_json::to_value(key.algorithm)
				.ok()
				.and_then(|v| v.as_str().map(str::to_string))
				.unwrap_or_default()
		);
	}
	if let Some(dkim) = &outcome.dkim {
		let _ = writeln!(out, "[dkim]: {dkim}");
	}
	for note in &plan.skipped {
		let _ = writeln!(out, "skipped {}: {}", note.item, note.reason);
	}
	for note in &outcome.notes {
		let _ = writeln!(out, "note: {note}");
	}
	match passwords {
		Some(Passwords::File(path)) if !outcome.accounts_added.is_empty() => {
			let _ = writeln!(
				out,
				"passwords: the accounts are disabled for login; their temporary passwords are in {}. \
				 Hand each one over, then `epistle account enable NAME`",
				crate::cli::staging::shown(&path.display().to_string())
			);
		}
		Some(Passwords::Reset) if !outcome.accounts_added.is_empty() => {
			let _ = writeln!(
				out,
				"passwords: the accounts are disabled for login with no known password. Set each \
				 with `epistle account password NAME`, then `epistle account enable NAME`"
			);
		}
		_ => {}
	}
	if !plan.manual.is_empty() {
		let _ = writeln!(out, "to do by hand:");
		for step in &plan.manual {
			let _ = writeln!(out, "  - {step}");
		}
	}
}

#[cfg(test)]
#[path = "migrate_config_tests.rs"]
mod tests;
