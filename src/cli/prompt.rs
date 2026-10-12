//! Interactive prompts on the CLI.
//!
//! Every question goes to stderr, never stdout, so `--json` output stays
//! parseable. A run is interactive when stdin and stderr are both terminals.
//! Without a terminal nothing is asked: a destructive command refuses unless
//! `--yes` was given, and a secret is read as one line from stdin, as scripts
//! have always piped it.
//!
//! Secrets are read with terminal echo off whenever stdin is a terminal, even
//! when stderr is redirected and no question is printed. [`EchoOff`] restores
//! the terminal when the read returns by any path, and restores it from a
//! signal handler when Ctrl-C, SIGTERM or SIGHUP ends the process mid-read.
//!
//! The functions taking a [`Console`] hold the logic; the command handlers
//! call the entry points ([`confirm_destructive`], [`new_password`],
//! [`secret_line`]), which build the console from the real stdin and stderr.
//! Tests swap that source through the `script` module, so the code under test is
//! the code that runs in production.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use crate::cli::style;

#[cfg(unix)]
#[path = "prompt_echo.rs"]
mod echo;
#[cfg(test)]
#[path = "prompt_script.rs"]
pub(crate) mod script;

#[cfg(unix)]
use echo::EchoOff;

/// An answer to a yes/no question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
	Yes,
	No,
}

/// Where one command asks its questions.
pub(crate) struct Console<'a> {
	/// Someone can answer: stdin and stderr are terminals.
	pub(crate) interactive: bool,
	/// The terminal stdin reads from, whose echo a secret read turns off.
	/// `None` when stdin is not a terminal.
	pub(crate) tty: Option<libc::c_int>,
	/// Where answers and secrets are read from.
	pub(crate) input: &'a mut dyn BufRead,
	/// Where questions and errors are written (stderr).
	pub(crate) err: &'a mut dyn Write,
}

/// Where a console reads the operator's answers from.
pub(crate) enum Input<'a> {
	/// The process's stdin.
	Stdin,
	/// A reader the caller already holds on stdin.
	Reader(&'a mut dyn BufRead),
	/// The controlling terminal (`/dev/tty`), for a command whose stdin
	/// carries data, such as `restore` reading the archive.
	Terminal,
}

/// How a secret read ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Secret {
	/// The typed value, without its line ending.
	Read(String),
	/// End of input before any line.
	Eof,
	/// An empty line.
	Blank,
	/// The two typed values differ.
	Mismatch,
	/// Reading failed, or echo could not be turned off.
	Failed(String),
}

/// The message printed when the two typed passwords differ.
pub(crate) const MISMATCH: &str = "passwords do not match";

/// The question the second read of a new password asks.
pub(crate) const REPEAT: &str = "Repeat password";

/// True when both stdin and stderr are terminals: there is someone to answer
/// and they can see the question.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn is_interactive() -> bool {
	use std::io::IsTerminal;
	std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Ask `question` and read one yes/no line. A non-interactive console reads
/// nothing and answers no. An empty line takes the default: no when
/// `default_no` is set.
pub(crate) fn confirm(console: &mut Console<'_>, question: &str, default_no: bool) -> Answer {
	if !console.interactive {
		return Answer::No;
	}
	let _ = write!(console.err, "{question} ");
	let _ = console.err.flush();
	let mut line = String::new();
	match console.input.read_line(&mut line) {
		Ok(0) | Err(_) => {
			let _ = writeln!(console.err);
			Answer::No
		}
		Ok(_) => parse_yes_no(&line, default_no),
	}
}

/// `y` or `yes`, in any case, is yes; anything else is no; an empty line is
/// the default.
fn parse_yes_no(line: &str, default_no: bool) -> Answer {
	let trimmed = line.trim();
	if trimmed.is_empty() {
		return if default_no { Answer::No } else { Answer::Yes };
	}
	if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
		Answer::Yes
	} else {
		Answer::No
	}
}

/// Read a secret. With `twice` set and an interactive console the value is
/// asked a second time under [`REPEAT`] and the two must agree. Echo is off
/// on the terminal for every read; a console that is not interactive prints
/// no question and reads one line.
pub(crate) fn read_secret(console: &mut Console<'_>, question: &str, twice: bool) -> Secret {
	let echo = match hide_input(console.tty) {
		Ok(echo) => echo,
		Err(error) => return Secret::Failed(error),
	};
	if !console.interactive {
		return read_line(console.input);
	}
	if echo.is_none() {
		return Secret::Failed("stdin is not a terminal, so echo cannot be turned off".into());
	}
	let first = match ask_hidden(console, question) {
		Secret::Read(value) => value,
		other => return other,
	};
	if !twice {
		return Secret::Read(first);
	}
	match ask_hidden(console, REPEAT) {
		Secret::Read(second) if second == first => Secret::Read(first),
		Secret::Read(_) => Secret::Mismatch,
		other => other,
	}
}

/// Turn echo off on `tty` for as long as the returned guard lives.
#[cfg(unix)]
fn hide_input(tty: Option<libc::c_int>) -> Result<Option<EchoOff>, String> {
	tty.map(EchoOff::new).transpose()
}

/// No termios here: a terminal cannot be read without echo, so refuse.
#[cfg(not(unix))]
fn hide_input(tty: Option<libc::c_int>) -> Result<Option<()>, String> {
	match tty {
		Some(_) => Err("turning off terminal echo is not supported on this platform".into()),
		None => Ok(None),
	}
}

/// Print `question`, read one line with echo already off, and end the line
/// the operator typed on, since the Enter they pressed was not echoed.
fn ask_hidden(console: &mut Console<'_>, question: &str) -> Secret {
	let _ = write!(console.err, "{question}: ");
	let _ = console.err.flush();
	let outcome = read_line(console.input);
	let _ = writeln!(console.err);
	outcome
}

/// Read one line without its line ending.
fn read_line(input: &mut dyn BufRead) -> Secret {
	let mut line = String::new();
	match input.read_line(&mut line) {
		Ok(0) => Secret::Eof,
		Ok(_) => {
			let value = line.trim_end_matches(['\n', '\r']);
			if value.is_empty() {
				Secret::Blank
			} else {
				Secret::Read(value.to_string())
			}
		}
		Err(error) => Secret::Failed(error.to_string()),
	}
}

/// The refusal printed when a destructive command has nobody to ask and no
/// `--yes`.
pub(crate) fn refused_message(action: &str) -> String {
	format!(
		"{action} was not confirmed; re-run with --yes to apply, or answer the question on a terminal"
	)
}

/// The message printed when the operator answers no.
pub(crate) fn cancelled_message(action: &str) -> String {
	format!("{action} cancelled; nothing was changed")
}

/// Gate a destructive `action`. `yes` (`--yes`) skips the question. On a
/// terminal `question` is asked and anything but yes cancels; without a
/// terminal the command refuses with a message that names `--yes`. Both
/// refusals return exit code 2 and change nothing.
pub(crate) fn confirm_with(
	console: &mut Console<'_>,
	action: &str,
	question: &str,
	yes: bool,
) -> Result<(), ExitCode> {
	if yes {
		return Ok(());
	}
	if !console.interactive {
		style::error_to(&mut console.err, refused_message(action));
		return Err(ExitCode::from(2));
	}
	match confirm(console, question, true) {
		Answer::Yes => Ok(()),
		Answer::No => {
			style::error_to(&mut console.err, cancelled_message(action));
			Err(ExitCode::from(2))
		}
	}
}

/// [`confirm_with`] on the process's stdin and stderr.
pub(crate) fn confirm_destructive(action: &str, question: &str, yes: bool) -> Result<(), ExitCode> {
	if yes {
		return Ok(());
	}
	with_console(Input::Stdin, |console| {
		confirm_with(console, action, question, yes)
	})
}

/// [`confirm_destructive`] for a command whose stdin is data: the question
/// is answered on the controlling terminal, and the run counts as
/// interactive only when stderr and that terminal are both there.
pub(crate) fn confirm_destructive_on_terminal(
	action: &str,
	question: &str,
	yes: bool,
) -> Result<(), ExitCode> {
	if yes {
		return Ok(());
	}
	with_console(Input::Terminal, |console| {
		confirm_with(console, action, question, yes)
	})
}

/// Read a new account password from `reader`: asked twice with echo off on a
/// terminal, one line otherwise, then checked against the password policy.
/// Every refusal (no input, blank, mismatch, a policy rule) is printed with
/// the reason and returns `None`.
pub(crate) fn new_password(question: &str, reader: &mut dyn BufRead) -> Option<String> {
	with_console(Input::Reader(reader), |console| {
		let message = match read_secret(console, question, true) {
			Secret::Read(value) => match crate::password::validate(&value) {
				Ok(()) => return Some(value),
				Err(rejection) => rejection.message().to_string(),
			},
			Secret::Eof => "no input: pipe or type the value on stdin".to_string(),
			Secret::Blank => "input must not be empty".to_string(),
			Secret::Mismatch => MISMATCH.to_string(),
			Secret::Failed(error) => format!("reading stdin: {error}"),
		};
		style::error_to(&mut console.err, message);
		None
	})
}

/// Read one secret line (a relay password, a webhook secret) from `reader`,
/// with echo off on a terminal. The caller validates the value.
pub(crate) fn secret_line(what: &str, reader: &mut dyn BufRead) -> Secret {
	with_console(Input::Reader(reader), |console| {
		let mut question = what.to_string();
		if let Some(first) = question.get_mut(..1) {
			first.make_ascii_uppercase();
		}
		read_secret(console, &question, false)
	})
}

/// Build the console for this process and run `body` with it.
#[cfg(not(test))]
fn with_console<R>(input: Input<'_>, body: impl FnOnce(&mut Console<'_>) -> R) -> R {
	use std::io::IsTerminal;
	let mut err = style::stderr();
	let stdin_tty = std::io::stdin().is_terminal();
	let tty = stdin_tty.then_some(libc::STDIN_FILENO);
	let interactive = is_interactive();
	match input {
		Input::Reader(input) => body(&mut Console {
			interactive,
			tty,
			input,
			err: &mut err,
		}),
		Input::Stdin => body(&mut Console {
			interactive,
			tty,
			input: &mut std::io::stdin().lock(),
			err: &mut err,
		}),
		Input::Terminal => {
			let terminal = std::fs::File::open("/dev/tty").ok();
			let interactive = terminal.is_some() && std::io::stderr().is_terminal();
			let mut reader: Box<dyn BufRead> = match terminal {
				Some(file) => Box::new(std::io::BufReader::new(file)),
				None => Box::new(std::io::empty()),
			};
			body(&mut Console {
				interactive,
				tty: None,
				input: &mut reader,
				err: &mut err,
			})
		}
	}
}

/// The process's stdin, for a handler that takes its reader as an argument.
#[cfg(not(test))]
pub(crate) fn stdin() -> std::io::StdinLock<'static> {
	std::io::stdin().lock()
}

#[cfg(test)]
pub(crate) use script::stdin;
#[cfg(test)]
use script::with_console;

#[cfg(test)]
#[path = "prompt_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "prompt_tests_tty.rs"]
mod tests_tty;
