//! `epistle init`: the first-run assistant that lays down the answers,
//! generates the keys, and writes the configuration file.
//!
//! The public addresses the operator leaves out are proposed from the
//! host's own interfaces (`detect`). DNS publishing is another part and
//! is deliberately out of scope here: the plan step list always carries
//! the `dns` step as `not implemented in this build`.

mod answers;
mod answers_none;
mod apply;
mod assistant;
mod compose;
mod detect;
mod first_account;
pub(crate) mod images;
mod plan;
mod ptr;
mod regenerate;
pub(crate) mod resources;

pub use answers::Answers;
pub use compose::compose_file_path;
pub(crate) use compose::{DATABASE_NAME, DATABASE_PASSWORD_FILE, DATABASE_USER, HOST_EPISTLE_PATH};
pub(crate) use compose::{MAIL_STOP_GRACE_SECS, update_listener_ports};
pub(crate) use regenerate::regenerate;
#[cfg(test)]
pub(crate) use regenerate::rendered_for_tests;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use answers::Warning;
use answers_none::Declined;
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
	let probes = Probes {
		detector: &detect::LiveDetector,
		resolver: &ptr::system_resolver,
	};
	run_with(args, &probes, &mut crate::cli::style::stderr())
}

/// What `init` reads from the host and the network without changing
/// either: the interface list and the resolver behind the PTR block.
/// Injected so the tests use a scripted detector and the fake resolver.
struct Probes<'a> {
	detector: &'a dyn detect::Detector,
	/// Built only when there is an address to look up.
	resolver: &'a dyn Fn() -> Option<Box<dyn crate::spf::DnsLookup>>,
}

/// [`run`] with the probes and the stream for the detection notices and
/// the PTR block injected.
fn run_with(args: Args, probes: &Probes, out: &mut dyn Write) -> ExitCode {
	let detector = probes.detector;
	if args.print_answers {
		println!("{}", Answers::template());
		return ExitCode::from(EXIT_OK);
	}
	let mut first_password = None;
	let mut answers = match args.answers.as_ref() {
		Some(path) => match read_answers(path) {
			Ok((mut answers, declined)) => {
				detect::fill_missing(&mut answers, declined, detector, out);
				answers
			}
			Err(error) => {
				crate::cli::style::error(error);
				return ExitCode::from(EXIT_INVALID);
			}
		},
		None => match read_interactive(detector) {
			Ok(filled) => {
				first_password = filled.first_password;
				filled.answers
			}
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
		let _ = writeln!(out, "dry-run: nothing was written");
		report_ptr(&answers, probes, out);
		return ExitCode::from(EXIT_OK);
	}
	if args.answers.is_none() && !confirm(std::io::stdin().lock(), crate::cli::style::stderr()) {
		let mut out = crate::cli::style::stderr();
		let _ = writeln!(out, "aborted: nothing was written");
		return ExitCode::from(EXIT_OK);
	}
	// From an answers file the password is read now, after the plan and
	// before anything is written, so a refused one leaves nothing behind.
	if let (Some(first), None) = (&answers.first_account, &first_password) {
		match first_account::read_password(first) {
			Ok(password) => first_password = Some(password),
			Err(why) => {
				crate::cli::style::error(format_args!("first_account: {why}"));
				return ExitCode::from(EXIT_INVALID);
			}
		}
	}
	let mut outcome = apply::apply(&answers);
	if outcome.error.is_none()
		&& let (Some(first), Some(password)) = (&answers.first_account, &first_password)
		&& let Err(error) =
			first_account::create(first, password, &answers.config_path, &mut outcome.report)
	{
		outcome.error = Some(error);
	}
	if !outcome.report.steps.is_empty() {
		render_report(&outcome.report);
	}
	match outcome.error {
		None => {
			report_ptr(&answers, probes, out);
			ExitCode::from(EXIT_OK)
		}
		Some(error) => {
			crate::cli::style::error(error);
			ExitCode::from(EXIT_PARTIAL)
		}
	}
}

/// The answers file, and the address families it sets to `"none"`.
fn read_answers(path: &PathBuf) -> Result<(Answers, Declined), ApplyError> {
	let raw = std::fs::read_to_string(path)
		.map_err(|error| ApplyError::ConfigRead(path.clone(), error))?;
	let answers = toml::from_str(&raw).map_err(|error| {
		// Parser messages and source excerpts can both include credential values.
		let mut diagnostic = "invalid answers TOML".to_string();
		if let Some(span) = error.span() {
			let prefix = &raw[..span.start];
			let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
			let column = prefix.rsplit('\n').next().unwrap_or("").chars().count() + 1;
			diagnostic.push_str(&format!(" at line {line}, column {column}"));
		}
		ApplyError::ConfigEncode(diagnostic)
	})?;
	Ok((answers, answers_none::declined(&raw)))
}

fn read_interactive(detector: &dyn detect::Detector) -> Result<assistant::Filled, ()> {
	let mut stdin = std::io::stdin().lock();
	let mut stderr = crate::cli::style::stderr();
	assistant::run(&mut stdin, &mut stderr, detector)
}

fn confirm<R: std::io::BufRead>(reader: R, out: impl std::io::Write) -> bool {
	let mut reader = reader;
	let mut out = out;
	assistant::confirm(&mut reader, &mut out).unwrap_or(false)
}

/// The reverse-DNS block for the addresses that ended up in `answers`,
/// typed, read from the file or detected. Informational only: the caller
/// returns the same exit code whatever it says, and without an address
/// there is no block and no resolver is built.
fn report_ptr(answers: &Answers, probes: &Probes, out: &mut dyn Write) {
	let addresses: Vec<std::net::IpAddr> = [
		answers.public_ipv4.map(std::net::IpAddr::V4),
		answers.public_ipv6.map(std::net::IpAddr::V6),
	]
	.into_iter()
	.flatten()
	.collect();
	if addresses.is_empty() {
		return;
	}
	let resolver = (probes.resolver)();
	ptr::render(&answers.hostname, &addresses, resolver.as_deref(), out);
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

#[cfg(test)]
#[path = "init_tests_parse_privacy.rs"]
mod tests_parse_privacy;

#[cfg(test)]
#[path = "init_detect_tests.rs"]
mod tests_detect;

#[cfg(test)]
#[path = "init_ptr_tests.rs"]
mod tests_ptr;

#[cfg(test)]
#[path = "init_first_account_tests.rs"]
mod tests_first_account;
