//! Decorated status output for the CLI. Every byte this module writes goes to
//! stderr: the functions bind it themselves, and the one that takes a sink
//! (`warn_to`) is handed [`stderr`] by `dispatch`. stdout is reserved for
//! command data (archives, keys, listings) and is never decorated.
//!
//! Colour is decided by `anstream` from `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`
//! and whether stderr is a terminal. Forced colour (`CLICOLOR_FORCE=1`) is the
//! gate an integration test uses to make sure stderr actually carries escape
//! codes; the same code path serves a real user running `epistle` from a
//! terminal.
//!
//! Progress is a single rewritable line on stderr, throttled to 100 ms and only
//! emitted when stderr is a terminal. When stderr is not a terminal (CI, a
//! redirected log) `tick` is a no-op and `finish` prints the summary once. No
//! animation, no thread.

use std::io::IsTerminal;
use std::io::Write;
use std::time::{Duration, Instant};

/// Minimum interval between two rewrites of the progress line.
const THROTTLE: Duration = Duration::from_millis(100);

/// Return to column 0, erase the whole line (CSI 2K), return again.
const CLEAR_LINE: &str = "\r\x1b[2K\r";

/// The stderr handle every decorator in this module writes through, and the
/// sink `dispatch` hands to a command that takes its warning writer as a
/// parameter.
///
/// All decoration routes through `anstream`, which chooses to emit ANSI
/// sequences or pass the text through unchanged based on environment variables
/// (`NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`) and whether the sink is a
/// terminal. Nothing else in the CLI makes that decision.
pub(crate) fn stderr() -> anstream::AutoStream<std::io::Stderr> {
	anstream::stderr()
}

/// Whether stderr is a terminal right now.
fn stderr_is_terminal() -> bool {
	std::io::stderr().is_terminal()
}

/// `error: <msg>` on stderr, with `error:` bold red.
pub(crate) fn error(msg: impl std::fmt::Display) {
	let mut out = stderr();
	let _ = writeln!(
		out,
		"{prefix}error:{reset} {msg}",
		prefix = anstyle::Style::new()
			.bold()
			.fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
		reset = anstyle::Reset,
	);
}

/// `warning: <msg>` on stderr, with `warning:` bold yellow.
pub(crate) fn warn(msg: impl std::fmt::Display) {
	warn_to(&mut stderr(), msg);
}

/// `warning: <msg>` written to `out`, with `warning:` bold yellow.
///
/// For commands that take their warning sink as a parameter (`backup`). The
/// style is written unconditionally; the caller passes [`stderr`] so the
/// colour decision is still made in one place, and a test passes a buffer.
pub(crate) fn warn_to(out: &mut impl Write, msg: impl std::fmt::Display) {
	let _ = writeln!(
		out,
		"{prefix}warning:{reset} {msg}",
		prefix = anstyle::Style::new()
			.bold()
			.fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
		reset = anstyle::Reset,
	);
}

/// A single rewritable progress line on stderr.
///
/// One tick per item, throttle 100 ms, terminal-only. When stderr is not a
/// terminal, `tick` does nothing and `finish` prints the summary once. The
/// final summary is the only output a piped run sees.
///
/// The sink and the terminal decision are fields so the unit tests can drive
/// the type against a buffer; `start` is the only constructor the commands use
/// and it always binds stderr.
pub(crate) struct Progress<W: Write = anstream::AutoStream<std::io::Stderr>> {
	label: String,
	out: W,
	on_terminal: bool,
	last_emit: Option<Instant>,
}

impl Progress {
	/// Start a progress line for `label`. The label is the fixed prefix the
	/// operator sees (e.g. `importing`). Whether stderr is a terminal is read
	/// once, here.
	pub(crate) fn start(label: &str) -> Self {
		Self::with_sink(label, stderr(), stderr_is_terminal())
	}
}

impl<W: Write> Progress<W> {
	/// A progress line that writes to `out`. `on_terminal` decides whether
	/// ticks are drawn at all.
	fn with_sink(label: &str, out: W, on_terminal: bool) -> Self {
		Self {
			label: label.to_owned(),
			out,
			on_terminal,
			last_emit: None,
		}
	}

	/// One item completed. No-op off a terminal. Throttled to one rewrite
	/// every 100 ms on one; the first tick always rewrites so a short run
	/// still shows a progress line.
	pub(crate) fn tick(&mut self, done: usize) {
		self.tick_at(done, Instant::now());
	}

	/// `tick` with the clock reading passed in, so the throttle can be
	/// exercised without waiting.
	fn tick_at(&mut self, done: usize, now: Instant) {
		if !self.on_terminal {
			return;
		}
		if let Some(previous) = self.last_emit
			&& now.duration_since(previous) < THROTTLE
		{
			return;
		}
		self.last_emit = Some(now);
		let _ = write!(self.out, "\r{} {}", self.label, done);
		let _ = self.out.flush();
	}

	/// End the line. Prints `summary` once and moves to the next line.
	///
	/// On a terminal the in-progress `\r...` line is cleared first so the
	/// operator does not see the last partial count and the summary stacked
	/// on top of each other. The summary itself is plain text; no `ok:`
	/// prefix.
	pub(crate) fn finish(mut self, summary: &str) {
		if self.on_terminal {
			let _ = write!(self.out, "{CLEAR_LINE}");
		}
		let _ = writeln!(self.out, "{summary}");
	}
}

#[cfg(test)]
#[path = "style_tests.rs"]
mod tests;
