//! `epistle rotate --accounts-only --dry-run`: the accounts a reset would
//! cover, and the ones it cannot reach. It reads the configuration and the
//! account store and writes nothing, not even the rotation's directory.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::config::Config;

use super::run::steps::accounts::{accounts, notes};

/// Print what `rotate --accounts-only` would reset.
pub(super) fn dry_run(path: &Path, json: bool, out: &mut impl Write) -> ExitCode {
	let listed = Config::load(path)
		.map_err(|error| format!("cannot load {}: {error}", path.display()))
		.and_then(|config| Ok((accounts(&config)?, notes(&config))));
	let (names, notes) = match listed {
		Ok(listed) => listed,
		Err(message) => {
			crate::cli::style::error(message);
			return ExitCode::FAILURE;
		}
	};
	let written = if json {
		serde_json::to_writer(
			&mut *out,
			&serde_json::json!({ "dry_run": true, "accounts": names, "notes": notes }),
		)
		.map_err(std::io::Error::from)
		.and_then(|()| writeln!(out))
	} else {
		text(out, &names, &notes)
	};
	match written {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			eprintln!("cannot write the plan: {error}");
			ExitCode::FAILURE
		}
	}
}

fn text(out: &mut impl Write, names: &[String], notes: &[String]) -> std::io::Result<()> {
	writeln!(
		out,
		"Dry run: {} accounts would lose their password and second factor and sign in nowhere \
		 until an administrator sets a new password:",
		names.len()
	)?;
	for name in names {
		writeln!(out, "  {name}")?;
	}
	if !notes.is_empty() {
		writeln!(out, "Not reached by the reset:")?;
		for note in notes {
			writeln!(out, "  - {note}")?;
		}
	}
	Ok(())
}
