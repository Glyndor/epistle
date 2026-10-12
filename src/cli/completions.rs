//! Shell completion scripts and man pages.
//!
//! Both are rendered from the clap definition at the moment they are asked
//! for, so neither can drift from the parser the binary actually runs. The
//! Debian package calls `epistle manpages` and `epistle completions` once at
//! build time and ships the output; nothing here runs on a server.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::{CommandFactory, ValueEnum};

use super::{Cli, style};

/// The shells `epistle completions` writes a script for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
	/// GNU Bash, through the bash-completion framework.
	Bash,
	/// Zsh, as a `_epistle` function for `compinit`.
	Zsh,
	/// Fish, as a file under `vendor_completions.d`.
	Fish,
}

impl From<CompletionShell> for clap_complete::Shell {
	fn from(shell: CompletionShell) -> Self {
		match shell {
			CompletionShell::Bash => clap_complete::Shell::Bash,
			CompletionShell::Zsh => clap_complete::Shell::Zsh,
			CompletionShell::Fish => clap_complete::Shell::Fish,
		}
	}
}

/// Render the completion script for `shell`.
///
/// Rendered into memory rather than straight to stdout: the generators panic
/// on a failed write, and a closed pipe should end in an error line, not a
/// panic.
pub(super) fn completion_script(shell: CompletionShell) -> Vec<u8> {
	let mut script = Vec::new();
	clap_complete::generate(
		clap_complete::Shell::from(shell),
		&mut Cli::command(),
		"epistle",
		&mut script,
	);
	script
}

/// Write the man pages into `dir`, creating it when missing: `epistle.1` and
/// one `epistle-<subcommand>.1` per visible subcommand, nested ones included.
/// Hidden commands (the flat aliases and this one) get no page.
pub(super) fn write_manpages(dir: &Path) -> std::io::Result<()> {
	std::fs::create_dir_all(dir)?;
	clap_mangen::generate_to(Cli::command(), dir)
}

/// `epistle completions <shell>`: the script on stdout.
pub(super) fn run_completions(shell: CompletionShell) -> ExitCode {
	match std::io::stdout()
		.lock()
		.write_all(&completion_script(shell))
	{
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			style::error(format_args!("writing the completion script: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// `epistle manpages <dir>`: one page per command into `dir`.
pub(super) fn run_manpages(dir: &Path) -> ExitCode {
	match write_manpages(dir) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			style::error(format_args!(
				"writing man pages to {}: {error}",
				dir.display()
			));
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "completions_tests.rs"]
mod tests;
