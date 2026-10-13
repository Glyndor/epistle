//! Terminal decoration: symbols, colour and width fitting for a stream that
//! is a terminal, and nothing at all for one that is not.
//!
//! A stream is decorated only when all of these hold, each stream decided on
//! its own: it is a terminal, `NO_COLOR` is unset or empty, `TERM` is not
//! `dumb`, and the command was not asked for `--json`. Anything else gets the
//! plain output byte for byte, which is what scripts and the tests that pin
//! the plain form read. `CLICOLOR_FORCE` does not decorate a pipe: it forces
//! the colour of the `error:` prefix through `anstream`, never a table or a
//! spinner into a file.
//!
//! The renderers take a [`Decor`] (colour on or off, the width to fit) so the
//! same function is exercised against a fake terminal in the tests; only
//! [`stdout`] reads the real stream.

pub(crate) mod table;

use std::ffi::OsStr;

use anstyle::{AnsiColor, Style};

/// Width assumed when a terminal does not report its size.
const FALLBACK_WIDTH: usize = 80;

/// Appended to a cell or a row that had to be shortened.
pub(crate) const ELLIPSIS: char = '…';

/// How a decorated stream is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decor {
	/// Emit colour escapes. The symbols are drawn either way.
	pub(crate) colour: bool,
	/// Columns a line may take; a longer line is shortened, never wrapped.
	pub(crate) width: usize,
}

impl Decor {
	/// Decoration with colour, fitted to `width` columns.
	pub(crate) fn coloured(width: usize) -> Self {
		Decor {
			colour: true,
			width,
		}
	}
}

/// Whether a stream is decorated, from the facts that decide it. Pure, so
/// every combination is tested without a terminal.
pub(crate) fn decorates(
	is_terminal: bool,
	no_color: Option<&OsStr>,
	term: Option<&OsStr>,
	json: bool,
) -> bool {
	is_terminal
		&& !json
		&& no_color.is_none_or(OsStr::is_empty)
		&& term.is_none_or(|value| value != OsStr::new("dumb"))
}

/// The decoration for the stream on `fd`, or `None` for plain output.
#[cfg(not(test))]
fn for_fd(fd: libc::c_int, is_terminal: bool, json: bool) -> Option<Decor> {
	let no_color = std::env::var_os("NO_COLOR");
	let term = std::env::var_os("TERM");
	decorates(is_terminal, no_color.as_deref(), term.as_deref(), json)
		.then(|| Decor::coloured(width_of(fd)))
}

/// How stdout is drawn for a command run with (`json`) or without `--json`.
#[cfg(not(test))]
pub(crate) fn stdout(json: bool) -> Option<Decor> {
	use std::io::IsTerminal;
	for_fd(libc::STDOUT_FILENO, std::io::stdout().is_terminal(), json)
}

#[cfg(test)]
pub(crate) use fake::stdout;

/// The width of the terminal on `fd`, re-read on every call so a resize
/// between two redraws is honoured. A descriptor that is not a terminal, or
/// one that reports zero columns, gets [`FALLBACK_WIDTH`].
pub(crate) fn width_of(fd: libc::c_int) -> usize {
	// SAFETY: a zeroed winsize is valid storage and TIOCGWINSZ only writes
	// into it; a descriptor that is not a terminal returns an error.
	let mut size: libc::winsize = unsafe { std::mem::zeroed() };
	let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) };
	if rc != 0 || size.ws_col == 0 {
		FALLBACK_WIDTH
	} else {
		usize::from(size.ws_col)
	}
}

/// What a state means to the operator, which decides its symbol and colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
	/// Working, enabled, delivered: ✔ in green.
	Good,
	/// Needs a look: ⚠ in yellow.
	Warn,
	/// Broken or failed: ✘ in red.
	Bad,
	/// Off by choice, such as a disabled alias: ✘ dimmed. Red stays for
	/// failures, so a list of switched-off services does not read as broken.
	Off,
}

impl Tone {
	/// The symbol drawn before the state word.
	pub(crate) fn mark(self) -> &'static str {
		match self {
			Tone::Good => "✔",
			Tone::Warn => "⚠",
			Tone::Bad | Tone::Off => "✘",
		}
	}

	/// The style the symbol and the state word are painted in.
	pub(crate) fn style(self) -> Style {
		match self {
			Tone::Good => Style::new().fg_color(Some(AnsiColor::Green.into())),
			Tone::Warn => Style::new().fg_color(Some(AnsiColor::Yellow.into())),
			Tone::Bad => Style::new().fg_color(Some(AnsiColor::Red.into())),
			Tone::Off => Style::new().dimmed(),
		}
	}
}

/// The tone of a state word printed in a list: `enabled`, `ok`, `held`.
/// `None` for a word that carries no state.
pub(crate) fn tone_of(word: &str) -> Option<Tone> {
	match word {
		"ok" | "enabled" | "delivered" | "active" => Some(Tone::Good),
		"warn" | "deferred" | "held" | "expiring" => Some(Tone::Warn),
		"fail" | "failed" | "error" | "missing" => Some(Tone::Bad),
		"disabled" | "revoked" | "expired" => Some(Tone::Off),
		_ => None,
	}
}

/// `word` with its symbol in front when it carries a state, plain otherwise.
pub(crate) fn badge(word: &str) -> String {
	match tone_of(word) {
		Some(tone) => format!("{} {word}", tone.mark()),
		None => word.to_string(),
	}
}

/// `text` wrapped in `style` when `colour` is on, unchanged otherwise.
pub(crate) fn paint(style: Style, text: &str, colour: bool) -> String {
	if colour && !text.is_empty() {
		format!("{}{text}{}", style.render(), style.render_reset())
	} else {
		text.to_string()
	}
}

/// The number of columns `text` takes, counted in characters: the symbols
/// used here are one column wide in every terminal that draws them.
pub(crate) fn columns(text: &str) -> usize {
	text.chars().count()
}

/// `text` cut to at most `width` columns, ending in [`ELLIPSIS`] when it
/// was cut. A width of zero returns an empty string.
pub(crate) fn fit(text: &str, width: usize) -> String {
	if columns(text) <= width {
		return text.to_string();
	}
	if width == 0 {
		return String::new();
	}
	let mut out: String = text.chars().take(width - 1).collect();
	out.push(ELLIPSIS);
	out
}

/// [`fit`], then padded with spaces to exactly `width` columns.
pub(crate) fn pad(text: &str, width: usize) -> String {
	let fitted = fit(text, width);
	let fill = width.saturating_sub(columns(&fitted));
	format!("{fitted}{}", " ".repeat(fill))
}

/// Control characters escaped so a value read from a file cannot move the
/// cursor or repaint the terminal it is printed on.
pub(crate) fn sanitize(text: &str) -> String {
	text.chars()
		.flat_map(|c| {
			if c.is_control() {
				c.escape_default().collect::<Vec<_>>()
			} else {
				vec![c]
			}
		})
		.collect()
}

/// Test stand-in for [`stdout`]: plain unless a test says
/// otherwise, so a unit test never decorates because `cargo test` happens to
/// run in a terminal.
#[cfg(test)]
pub(crate) mod fake {
	use std::cell::Cell;

	use super::Decor;

	thread_local! {
		static STDOUT: Cell<Option<Decor>> = const { Cell::new(None) };
	}

	/// The test build's stdout decoration.
	pub(crate) fn stdout(json: bool) -> Option<Decor> {
		STDOUT.with(Cell::get).filter(|_| !json)
	}

	/// Run `body` as if stdout were a terminal drawn with `decor`.
	pub(crate) fn with_stdout<R>(decor: Decor, body: impl FnOnce() -> R) -> R {
		let previous = STDOUT.with(|slot| slot.replace(Some(decor)));
		let value = body();
		STDOUT.with(|slot| slot.set(previous));
		value
	}
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
