//! A command run on a terminal without the account, alias, domain or label
//! it needs: offer the ones that exist instead of a usage error.
//!
//! The command line is parsed as usual. Only when clap reports a missing
//! argument that names something that already exists (see `target`), and
//! stdin and stderr are both terminals, is a numbered list offered; the
//! picked value is added to the command line, which is parsed again. Any
//! other case (a pipe, a script, a cancelled pick, nothing to pick from)
//! ends exactly as it did before: clap's usage error and exit code 2.

mod choices;
mod target;

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::OnceLock;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};

use super::{Cli, prompt};

/// Picks one command line may need: an app password needs its account and
/// then its label.
const MAX_PICKS: usize = 3;

/// The command line after a pick, so a command that re-executes itself
/// (as the service account, or inside the stack) passes the picked value on.
static PICKED: OnceLock<Vec<OsString>> = OnceLock::new();

/// The arguments this process runs with, without the program name: the
/// command line as typed, or as completed by a pick.
pub(super) fn effective_args() -> Vec<OsString> {
	match PICKED.get() {
		Some(args) => args.iter().skip(1).cloned().collect(),
		None => std::env::args_os().skip(1).collect(),
	}
}

/// Parse this process's command line and run it, offering a pick for a
/// missing account, alias, domain or label on a terminal. Returns the exit
/// code of the command; a usage error exits from here with code 2.
pub fn run_from_env() -> ExitCode {
	let args: Vec<OsString> = std::env::args_os().collect();
	let error = match Cli::try_parse_from(&args) {
		Ok(cli) => return cli.run(),
		Err(error) => error,
	};
	if error.kind() == ErrorKind::MissingRequiredArgument && prompt::is_interactive() {
		// Run as root, the command re-executes as the service account,
		// which then asks with the store it owns.
		if let Ok(Some(code)) = super::rootless::reexecute() {
			return code;
		}
		if let Some(completed) = complete(&args)
			&& let Ok(cli) = Cli::try_parse_from(&completed)
		{
			let _ = PICKED.set(completed);
			return cli.run();
		}
	}
	error.exit()
}

/// `args` with every missing pickable argument picked on the prompt
/// console, or `None` when one cannot be picked.
pub(super) fn complete(args: &[OsString]) -> Option<Vec<OsString>> {
	let mut args = args.to_vec();
	for _ in 0..MAX_PICKS {
		let error = match Cli::try_parse_from(&args) {
			Ok(_) => return Some(args),
			Err(error) => error,
		};
		let want = target::want(&Cli::command(), &error, &args)?;
		let options = choices::list(&want.kind, &want.config).ok()?;
		let picked = prompt::pick(&want.kind.noun(), &options)?;
		args = target::insert(&args, &want.insert, &picked);
	}
	Cli::try_parse_from(&args).is_ok().then_some(args)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
