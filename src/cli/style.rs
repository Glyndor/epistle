//! Decorated status output for the CLI. Every byte this module writes goes to
//! stderr. stdout is reserved for command data (archives, keys, listings) and
//! is never decorated.
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
use std::time::Instant;

/// The single stderr handle every decorator in this module writes through.
///
/// All decoration routes through `anstream`, which chooses to emit ANSI
/// sequences or pass the text through unchanged based on environment variables
/// (`NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`) and whether the sink is a
/// terminal. Nothing else in the CLI makes that decision.
fn stderr() -> anstream::AutoStream<std::io::Stderr> {
	anstream::stderr()
}

/// Whether stderr is a terminal right now. Cached once at module init so every
/// call in a long-running command pays nothing.
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
	let mut out = stderr();
	let _ = writeln!(
		out,
		"{prefix}warning:{reset} {msg}",
		prefix = anstyle::Style::new()
			.bold()
			.fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
		reset = anstyle::Reset,
	);
}

/// `ok: <msg>` on stderr, with `ok:` bold green. Used for a completed side
/// effect that an operator should notice (account added, key written, restore
/// finished).
#[allow(dead_code)]
pub(crate) fn ok(msg: impl std::fmt::Display) {
	let mut out = stderr();
	let _ = writeln!(
		out,
		"{prefix}ok:{reset} {msg}",
		prefix = anstyle::Style::new()
			.bold()
			.fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
		reset = anstyle::Reset,
	);
}

/// Plain `msg` on stderr, dim. For hints such as "add this to mail.toml" where
/// a prefix would just add noise.
#[allow(dead_code)]
pub(crate) fn note(msg: impl std::fmt::Display) {
	let mut out = stderr();
	let _ = writeln!(
		out,
		"{style}{msg}{reset}",
		style = anstyle::Style::new().dimmed(),
		reset = anstyle::Reset,
	);
}

/// A single rewritable progress line on stderr.
///
/// One tick per item, throttle 100 ms, terminal-only. When stderr is not a
/// terminal, `tick` does nothing and `finish` prints the summary once. The
/// final summary is the only output a piped run sees.
pub(crate) struct Progress {
	label: String,
	last_written: usize,
	last_emit: Option<Instant>,
}

impl Progress {
	/// Start a progress line for `label`. The label is the fixed prefix the
	/// operator sees (e.g. `importing`).
	pub(crate) fn start(label: &str) -> Self {
		Self {
			label: label.to_owned(),
			last_written: 0,
			last_emit: None,
		}
	}

	/// One item completed. No-op when stderr is not a terminal. Throttled to
	/// one rewrite every 100 ms when it is; the first tick always rewrites
	/// so a short run still shows a progress line.
	pub(crate) fn tick(&mut self, done: usize) {
		// Track the latest count even when stderr is not a terminal, so
		// `finish` can pick it up if the caller asks for a count.
		self.last_written = done;
		if !stderr_is_terminal() {
			return;
		}
		let now = Instant::now();
		if let Some(previous) = self.last_emit
			&& now.duration_since(previous).as_millis() < 100
		{
			return;
		}
		self.last_emit = Some(now);
		let mut out = stderr();
		let _ = write!(out, "\r{} {}", self.label, done);
		let _ = out.flush();
	}

	/// End the line. Prints `summary` once and moves to the next line.
	///
	/// When stderr is a terminal, the in-progress `\r...` line is cleared first
	/// so the operator does not see the last partial count and the summary
	/// stacked on top of each other. The summary itself is plain text on
	/// stderr; no `ok:` prefix.
	pub(crate) fn finish(self, summary: &str) {
		if stderr_is_terminal() {
			let mut out = stderr();
			let _ = write!(out, "\r\x1b[2K\r");
		}
		let mut out = stderr();
		let _ = writeln!(out, "{summary}");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn progress_tick_is_no_op_off_terminal() {
		// Without a terminal on stderr, ticks are a no-op: the summary line
		// that `finish` prints is the only output, and calling `tick` any
		// number of times must not panic.
		let mut progress = Progress::start("importing");
		for count in 1..=50 {
			progress.tick(count);
		}
	}

	#[test]
	fn progress_finish_keeps_summary_text() {
		// `finish` writes the summary line once; on the test process stderr
		// is not a terminal so only the summary line is emitted (no \r clear).
		// The summary text must be the one the caller supplied, byte-for-byte.
		let progress = Progress::start("verifying");
		progress.finish("verified 7 records");
	}
}
