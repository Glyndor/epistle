//! `epistle init`: the first-run assistant that lays down the answers,
//! generates the keys, and writes the configuration file.
//!
//! Detection of public addresses and DNS publishing are other parts and
//! are deliberately out of scope here: the plan step list always
//! carries the `dns` step as `not implemented in this build`.

mod answers;
mod apply;
mod assistant;
mod plan;

pub use answers::Answers;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use answers::Warning;
use apply::ApplyError;
use plan::Plan;

/// Operator-facing arguments, already extracted by the clap layer.
#[derive(Debug)]
pub struct Args {
	/// Path to the answers file; `None` means interactive.
	pub answers: Option<PathBuf>,
	/// Print the plan only; do not touch anything.
	pub dry_run: bool,
	/// Print the answers template and exit.
	pub print_answers: bool,
}

/// Exit codes: 0 done or nothing to do; 1 a step failed after
/// effects were applied (the report names which step); 2 nothing
/// was touched, either because the answers were invalid or
/// because a precondition stopped the run before any effect.
const EXIT_OK: u8 = 0;
const EXIT_PARTIAL: u8 = 1;
const EXIT_INVALID: u8 = 2;

/// Run the `init` command. The flow is one code path: the assistant
/// fills the same `Answers` structure the file deserialises. Every
/// question validates through the same rule.
pub fn run(args: Args) -> ExitCode {
	if args.print_answers {
		println!("{}", Answers::template());
		return ExitCode::from(EXIT_OK);
	}
	let mut answers = match args.answers.as_ref() {
		Some(path) => match read_answers(path) {
			Ok(answers) => answers,
			Err(error) => {
				crate::cli::style::error(error);
				return ExitCode::from(EXIT_INVALID);
			}
		},
		None => match read_interactive() {
			Ok(filled) => filled.answers,
			Err(()) => return ExitCode::from(EXIT_INVALID),
		},
	};
	answers.normalise();
	match answers.validate() {
		Ok(warnings) => render_warnings(&warnings),
		Err(errors) => {
			for error in errors {
				crate::cli::style::error(format_args!("{error}"));
			}
			return ExitCode::from(EXIT_INVALID);
		}
	}
	let plan = match apply::plan(&answers) {
		Ok(plan) => plan,
		Err(error) => {
			// A plan failure means a precondition stopped the run
			// before any effect: an existing config that cannot be
			// parsed, an incomplete key pair, a permissions refusal
			// on the keys dir. Nothing has been written, so the
			// exit code that says "look at what landed on your
			// machine" (1) is the wrong signal. 2 widens to cover
			// this case: nothing was touched.
			crate::cli::style::error(error);
			return ExitCode::from(EXIT_INVALID);
		}
	};
	render_plan(&plan);
	if args.dry_run {
		let mut out = crate::cli::style::stderr();
		let _ = writeln!(out, "dry-run: nothing was written");
		return ExitCode::from(EXIT_OK);
	}
	if args.answers.is_none() && !confirm(std::io::stdin().lock(), crate::cli::style::stderr()) {
		let mut out = crate::cli::style::stderr();
		let _ = writeln!(out, "aborted: nothing was written");
		return ExitCode::from(EXIT_OK);
	}
	let outcome = apply::apply(&answers);
	if !outcome.report.steps.is_empty() {
		render_report(&outcome.report);
	}
	match outcome.error {
		None => ExitCode::from(EXIT_OK),
		Some(error) => {
			crate::cli::style::error(error);
			ExitCode::from(EXIT_PARTIAL)
		}
	}
}

fn read_answers(path: &PathBuf) -> Result<Answers, ApplyError> {
	let raw = std::fs::read_to_string(path)
		.map_err(|error| ApplyError::ConfigRead(path.clone(), error))?;
	toml::from_str(&raw).map_err(|error| ApplyError::ConfigEncode(error.to_string()))
}

fn read_interactive() -> Result<assistant::Filled, ()> {
	let mut stdin = std::io::stdin().lock();
	let mut stderr = crate::cli::style::stderr();
	assistant::run(&mut stdin, &mut stderr)
}

fn confirm<R: std::io::BufRead>(reader: R, out: impl std::io::Write) -> bool {
	let mut reader = reader;
	let mut out = out;
	assistant::confirm(&mut reader, &mut out).unwrap_or(false)
}

fn render_warnings(warnings: &[Warning]) {
	for warning in warnings {
		crate::cli::style::warn(format_args!("{warning}"));
	}
}

fn render_plan(plan: &Plan) {
	let mut out = crate::cli::style::stderr();
	let _ = writeln!(out, "plan:");
	let _ = plan.write_to(&mut StringWriter::new(&mut out));
}

fn render_report(report: &apply::Report) {
	let mut out = crate::cli::style::stderr();
	let _ = writeln!(out, "report:");
	let _ = report.write_to(&mut out);
}

/// Tiny `fmt::Write` adapter that proxies into a `std::io::Write`.
struct StringWriter<W: std::io::Write> {
	inner: W,
}

impl<W: std::io::Write> StringWriter<W> {
	fn new(inner: W) -> Self {
		Self { inner }
	}
}

impl<W: std::io::Write> std::fmt::Write for StringWriter<W> {
	fn write_str(&mut self, s: &str) -> std::fmt::Result {
		self.inner
			.write_all(s.as_bytes())
			.map_err(|_| std::fmt::Error)
	}
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "init_answers_errors_tests.rs"]
mod tests_answers_errors;
