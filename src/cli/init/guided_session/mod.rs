//! Process wiring for the injected questions and private draft checkpoints.

use std::io::{self, IsTerminal, Write};

use super::{Answers, draft::Store};
use crate::cli::ui::prompt::{Policy, Prompt};

pub(super) fn policy(json: bool) -> Policy {
	Policy::new(
		std::io::stdin().is_terminal(),
		std::io::stderr().is_terminal(),
		json,
		&crate::cli::term::ProcessEnv::read().env(),
	)
}

/// Ask every question on a terminal. The caller decides whether this run is
/// one: [`policy`] with the process streams and the `--json` flag answers it,
/// and a run that is not a terminal keeps [`super::assistant`] instead.
pub(super) fn run(detector: &dyn super::detect::Detector, policy: Policy) -> io::Result<Answers> {
	let store = Store::process()?;
	let saved = store.load()?;
	let mut input = std::io::stdin().lock();
	let mut out = std::io::stderr().lock();
	let mut checkpoint = |answers: &crate::cli::ui::prompt::Answers| store.save(answers);
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy,
		answers: Default::default(),
		checkpoint: &mut checkpoint,
	};
	if !saved.is_empty()
		&& ui.confirm("Resume the saved init draft? Passwords must be entered again.")?
	{
		ui.answers = saved;
	}
	writeln!(
		ui.out,
		"Accepted answers are checkpointed at {}. Ctrl+C stops setup; run epistle init again to resume. Passwords and DNS tokens are never saved.",
		crate::cli::term::sanitize(&store.path().display().to_string())
	)?;
	super::guided::run(&mut ui, detector)
}

pub(super) fn confirm(reader: &mut impl io::BufRead, out: &mut impl Write, policy: Policy) -> bool {
	let mut checkpoint = |_: &crate::cli::ui::prompt::Answers| Ok(());
	let mut ui = Prompt {
		reader,
		out,
		policy,
		answers: Default::default(),
		checkpoint: &mut checkpoint,
	};
	ui.confirm("Apply this setup? This creates or updates the files listed above.")
		.unwrap_or(false)
}

pub(super) fn finished(answers: &Answers, out: &mut dyn Write) {
	let _ = writeln!(
		out,
		"Setup completed. Configuration: {}\nData and keys: {}\nNext commands:\n  epistle config-check\n  epistle stack up\n  epistle verify-dns\nFor a custom configuration, pass --config with the configuration path shown above.",
		crate::cli::term::sanitize(&answers.config_path.display().to_string()),
		crate::cli::term::sanitize(&answers.data_dir.display().to_string())
	);
	if let Err(error) = Store::process().and_then(|store| store.remove()) {
		let _ = writeln!(out, "warning: could not remove init draft: {error}");
	}
}

/// Retry password policy and confirmation errors without storing or echoing values.
pub(super) fn password_with(
	mut read: impl FnMut() -> crate::cli::prompt::Secret,
	out: &mut impl Write,
) -> io::Result<super::first_account::Password> {
	use crate::cli::prompt::Secret;
	loop {
		let value = match read() {
			Secret::Read(value) => value,
			Secret::Eof => {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"password input ended",
				));
			}
			Secret::Failed(_) => return Err(io::Error::other("password input failed")),
			Secret::Mismatch => {
				writeln!(out, "Passwords do not match. Try again.")?;
				continue;
			}
			Secret::Blank => {
				writeln!(
					out,
					"Password must not be empty. Use 12 to 64 printable ASCII characters. Try again."
				)?;
				continue;
			}
		};
		match crate::password::validate(&value) {
			Ok(()) => return Ok(super::first_account::Password::new(value)),
			Err(rejection) => writeln!(out, "{}. Try again.", rejection.message())?,
		}
	}
}

pub(super) fn password(name: &str) -> io::Result<super::first_account::Password> {
	let mut reader = crate::cli::prompt::stdin();
	let mut secret_out = std::io::stderr();
	let mut notices = std::io::stderr();
	let mut console = crate::cli::prompt::Console {
		interactive: true,
		tty: Some(libc::STDIN_FILENO),
		input: &mut reader,
		err: &mut secret_out,
	};
	password_with(
		|| crate::cli::prompt::read_secret(&mut console, &format!("Password for {name}"), true),
		&mut notices,
	)
}

#[cfg(test)]
mod tests;
