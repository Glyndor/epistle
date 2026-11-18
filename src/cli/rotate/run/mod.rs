//! `epistle rotate --all` without `--dry-run`: rotate every secret this
//! server can rotate, in order, and continue a run that was cut short.
//!
//! A new run plans its steps and checks what each one will check, so a
//! refusal comes before anything changes; then it asks once. Each step
//! records the value it will leave in the [journal], writes it,
//! and marks itself done. The next run after a cut continues from the
//! journal and applies a step only when its value is not on disk yet, so no
//! secret is rotated twice and none is left with a hash nobody holds the
//! secret of. The run stops at the first failure and leaves the journal for
//! the next one.

pub(super) mod journal;
mod report;
pub(super) mod secrets;
pub(super) mod steps;

#[cfg(test)]
mod tests;

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::config_edit::{Outcome, after_change_reporting};
use crate::cli::json_out::Reload;
use crate::cli::stack::StackAction;
use crate::config::Config;
use crate::storage::lock::FileLock;

pub(super) use journal::Scope;
use journal::{Intent, Journal, Kind, State};
use secrets::Secrets;
use steps::Context;

/// What the caller decided for this run.
pub(super) struct Options {
	/// Answer the question with yes.
	pub yes: bool,
	/// Print the result as one JSON object.
	pub json: bool,
	/// The time of the run, epoch seconds.
	pub now: u64,
	/// What the run goes through.
	pub scope: Scope,
}

/// Run or continue the rotation of the configuration at `path`.
pub(super) fn execute(
	path: &Path,
	options: Options,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> ExitCode {
	match drive(path, &options, out, status, restart) {
		Ok(code) => code,
		Err(Stop::Refused(message)) => {
			crate::cli::style::error(message);
			ExitCode::FAILURE
		}
		Err(Stop::Cancelled(code)) => code,
	}
}

/// Why a run ended without finishing.
enum Stop {
	/// The run stopped with this message; the journal, if any, is kept.
	Refused(String),
	/// The question was not answered with yes.
	Cancelled(ExitCode),
}

impl From<String> for Stop {
	fn from(message: String) -> Self {
		Stop::Refused(message)
	}
}

fn drive(
	path: &Path,
	options: &Options,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, Stop> {
	let config =
		Config::load(path).map_err(|error| format!("cannot load {}: {error}", path.display()))?;
	let dir = journal::dir(&config.data_dir);
	let _lock = lock(&config.data_dir)?.ok_or(
		"another `epistle rotate` or an `epistle backup` is running on this server".to_string(),
	)?;
	let context = Context {
		path,
		config: &config,
		now: options.now,
		scope: options.scope,
	};
	let command = options.scope.command();
	let (mut journal, resumed) = match Journal::load(&dir)? {
		Some(journal) if journal.scope != options.scope => {
			return Err(Stop::Refused(format!(
				"a `{}` run was cut short on this server; finish it with that command first",
				journal.scope.command()
			)));
		}
		Some(journal) => (journal, true),
		None => {
			let (steps, notes) = steps::plan(&context)
				.map_err(|reason| format!("`{command}` refused, nothing was changed: {reason}"))?;
			(
				Journal::new(options.scope, options.now, steps, notes),
				false,
			)
		}
	};
	crate::cli::prompt::confirm_destructive(
		command.trim_start_matches("epistle "),
		&report::question(&journal, resumed),
		options.yes,
	)
	.map_err(Stop::Cancelled)?;
	journal.save(&dir)?;
	let mut secrets = Secrets::open(&dir)?;
	let mut restart = Some(restart);
	let mut reload = None;
	for index in 0..journal.steps.len() {
		let mut run = Run {
			context: &context,
			dir: &dir,
			secrets: &mut secrets,
			status,
			restart: &mut restart,
			reload: &mut reload,
		};
		if let Err(error) = run.advance(&mut journal, index) {
			return Err(Stop::Refused(format!(
				"`{command}` stopped at {}: {error}. The steps before it are done and stay done; \
				 run `{command}` again to continue from this one",
				report::label(&journal.steps[index])
			)));
		}
	}
	report::print(out, &journal, &secrets, (resumed, reload), options.json)
		.map_err(|error| format!("cannot write the result: {error}"))?;
	secrets.remove()?;
	journal.archive(&dir, options.now)?;
	Ok(ExitCode::SUCCESS)
}

/// One step's work, with what it borrows from the run.
struct Run<'a, W, R> {
	context: &'a Context<'a>,
	dir: &'a Path,
	secrets: &'a mut Secrets,
	status: &'a mut W,
	restart: &'a mut Option<R>,
	reload: &'a mut Option<Reload>,
}

impl<W: Write, R: FnOnce(&Config, StackAction) -> ExitCode> Run<'_, W, R> {
	/// Take the step at `index` one state further until it is done.
	fn advance(&mut self, journal: &mut Journal, index: usize) -> Result<(), String> {
		let step = journal.steps[index].clone();
		match step.state {
			State::Done => return Ok(()),
			State::Pending => {
				let intent = steps::prepare(self.context, &step, self.secrets)?;
				journal.steps[index].intent = Some(intent.clone());
				journal.steps[index].state = State::Prepared;
				journal.save(self.dir)?;
				checkpoint();
				self.put(&step, &intent)?;
				checkpoint();
			}
			State::Prepared => {
				let intent = step
					.intent
					.clone()
					.ok_or("the journal records the step as prepared without its value")?;
				if steps::landed(self.context, &step, &intent)? {
					steps::settle(self.context, &step, &intent)?;
				} else {
					self.put(&step, &intent)?;
				}
			}
		}
		journal.steps[index].state = State::Done;
		journal.save(self.dir)?;
		checkpoint();
		Ok(())
	}

	/// Put the decided value in place: a store or file write, or the restart.
	fn put(&mut self, step: &journal::Step, intent: &Intent) -> Result<(), String> {
		if step.kind != Kind::Restart {
			return steps::apply(self.context, step, intent, self.secrets);
		}
		let restart = self
			.restart
			.take()
			.ok_or("the restart was asked for twice in one run")?;
		let (code, reload) = after_change_reporting(
			self.context.config,
			Outcome::Changed,
			true,
			self.status,
			restart,
		)
		.map_err(|error| error.to_string())?;
		*self.reload = Some(reload);
		if code != ExitCode::SUCCESS {
			return Err("the restart of the mail service failed".to_string());
		}
		Ok(())
	}
}

/// Take the rotation lock of `data_dir`, or `None` while someone holds it.
/// A run holds it from start to end, and a backup while it reads the data
/// directory, so the two never overlap: an archive cannot catch a run half
/// way, and a run cannot change the stores under a backup.
pub(in crate::cli) fn lock(data_dir: &Path) -> Result<Option<FileLock>, String> {
	let dir = journal::dir(data_dir);
	private_dir(&dir)?;
	FileLock::try_acquire(&dir.join("lock"))
		.map_err(|error| format!("cannot lock {}: {error}", dir.display()))
}

/// Create the run's directory readable by its owner alone.
fn private_dir(dir: &Path) -> Result<(), String> {
	use std::os::unix::fs::DirBuilderExt;
	match std::fs::DirBuilder::new().mode(0o700).create(dir) {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
		Err(error) => Err(format!("cannot create {}: {error}", dir.display())),
	}
}

/// A point between two writes of a step, where the kill tests stop the
/// process.
fn checkpoint() {
	#[cfg(test)]
	tests::abort::checkpoint();
}
