//! Terminal decoration: symbols, colour and width fitting for a stream that
//! is a terminal, and nothing at all for one that is not.
//!
//! A stream is decorated only when all of these hold, each stream decided on
//! its own: it is a terminal, `NO_COLOR` is unset or empty, `TERM` is not
//! `dumb`, `CLICOLOR` is not `0`, and the command was not asked for
//! `--json`. Anything else gets the plain output byte for byte, which is
//! what scripts and the tests that pin the plain form read.
//! `CLICOLOR_FORCE` does not decorate a pipe: it forces the colour of the
//! `error:` prefix and of clap's messages ([`colours`]), never a table or a
//! spinner into a file.
//!
//! The renderers take a [`Decor`] (colour on or off, the width to fit) so the
//! same function is exercised against a fake terminal in the tests; only
//! [`stdout`] and [`stderr`] read the real streams.

pub(crate) mod cursor;
pub(crate) mod live;
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

/// The environment variables that decide colour and decoration.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Env<'a> {
	/// `NO_COLOR`: set and not empty turns colour and decoration off.
	pub(crate) no_color: Option<&'a OsStr>,
	/// `TERM`: `dumb` turns colour and decoration off.
	pub(crate) term: Option<&'a OsStr>,
	/// `CLICOLOR`: `0` turns colour and decoration off.
	pub(crate) clicolor: Option<&'a OsStr>,
	/// `CLICOLOR_FORCE`: set and not `0` colours a stream that is not a
	/// terminal; it never decorates one.
	pub(crate) clicolor_force: Option<&'a OsStr>,
}

impl Env<'_> {
	fn no_color(&self) -> bool {
		self.no_color.is_some_and(|value| !value.is_empty())
	}

	fn forced(&self) -> bool {
		self.clicolor_force
			.is_some_and(|value| !value.is_empty() && value != OsStr::new("0"))
	}

	/// `TERM` and `CLICOLOR` allow colour on a terminal.
	fn allows(&self) -> bool {
		self.term.is_none_or(|value| value != OsStr::new("dumb"))
			&& self.clicolor.is_none_or(|value| value != OsStr::new("0"))
	}
}

/// The colour variables of this process. Owned, so a caller borrows them
/// as an [`Env`].
pub(crate) struct ProcessEnv([Option<std::ffi::OsString>; 4]);

impl ProcessEnv {
	/// Read the four variables once.
	pub(crate) fn read() -> Self {
		ProcessEnv(["NO_COLOR", "TERM", "CLICOLOR", "CLICOLOR_FORCE"].map(std::env::var_os))
	}

	/// The variables as an [`Env`].
	pub(crate) fn env(&self) -> Env<'_> {
		let [no_color, term, clicolor, clicolor_force] = &self.0;
		Env {
			no_color: no_color.as_deref(),
			term: term.as_deref(),
			clicolor: clicolor.as_deref(),
			clicolor_force: clicolor_force.as_deref(),
		}
	}
}

/// Whether a stream is decorated (symbols, tables, the spinner, the pick),
/// from the facts that decide it. Pure, so every combination is tested
/// without a terminal.
pub(crate) fn decorates(is_terminal: bool, env: &Env<'_>, json: bool) -> bool {
	is_terminal && !json && !env.no_color() && env.allows()
}

/// Whether a stream carries colour escapes: never with `NO_COLOR`, always
/// with `CLICOLOR_FORCE`, otherwise on a terminal that `TERM` and
/// `CLICOLOR` allow. The `error:` prefix and clap's own messages use this
/// answer, so the two never disagree; `CI` and the like play no part.
pub(crate) fn colours(is_terminal: bool, env: &Env<'_>) -> bool {
	!env.no_color() && (env.forced() || (is_terminal && env.allows()))
}

/// [`colours`] for this process's stderr (`stderr` set) or stdout, as the
/// choice handed to `anstream` and clap.
pub(crate) fn colour_choice(stderr: bool) -> anstream::ColorChoice {
	use std::io::IsTerminal;
	let is_terminal = if stderr {
		std::io::stderr().is_terminal()
	} else {
		std::io::stdout().is_terminal()
	};
	if colours(is_terminal, &ProcessEnv::read().env()) {
		anstream::ColorChoice::Always
	} else {
		anstream::ColorChoice::Never
	}
}

/// The decoration for the stream on `fd`, or `None` for plain output.
#[cfg(not(test))]
fn for_fd(fd: libc::c_int, is_terminal: bool, json: bool) -> Option<Decor> {
	decorates(is_terminal, &ProcessEnv::read().env(), json).then(|| Decor::coloured(width_of(fd)))
}

/// How stdout is drawn for a command run with (`json`) or without `--json`.
#[cfg(not(test))]
pub(crate) fn stdout(json: bool) -> Option<Decor> {
	use std::io::IsTerminal;
	for_fd(libc::STDOUT_FILENO, std::io::stdout().is_terminal(), json)
}

/// How stderr is drawn: the spinner and the step rows go there.
#[cfg(not(test))]
pub(crate) fn stderr(json: bool) -> Option<Decor> {
	use std::io::IsTerminal;
	for_fd(libc::STDERR_FILENO, std::io::stderr().is_terminal(), json)
}

#[cfg(test)]
pub(crate) use fake::{stderr, stdout};

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

/// Whether `c` is an invisible formatting character that can make text read
/// differently from what it is: zero-width marks, the bidirectional
/// overrides and isolates (U+202E turns the text after it around), the
/// invisible operators and the byte order mark.
pub(crate) fn is_invisible_format(c: char) -> bool {
	matches!(
		c,
		'\u{200B}'..='\u{200F}'
			| '\u{202A}'..='\u{202E}'
			| '\u{2060}'..='\u{2064}'
			| '\u{2066}'..='\u{2069}'
			| '\u{FEFF}'
	)
}

/// Control and invisible formatting characters escaped so a value read from
/// a file cannot move the cursor, repaint the terminal it is printed on or
/// reorder the text around it.
pub(crate) fn sanitize(text: &str) -> String {
	text.chars()
		.flat_map(|c| {
			if c.is_control() || is_invisible_format(c) {
				c.escape_default().collect::<Vec<_>>()
			} else {
				vec![c]
			}
		})
		.collect()
}

/// `0.4s`, `12.9s`, `1m03s`: tenths under a minute, whole seconds past it.
pub(crate) fn elapsed(duration: std::time::Duration) -> String {
	let secs = duration.as_secs_f64();
	if secs < 60.0 {
		format!("{secs:.1}s")
	} else {
		format!(
			"{}m{:02}s",
			duration.as_secs() / 60,
			duration.as_secs() % 60
		)
	}
}

/// Test stand-ins for [`stdout`] and [`stderr`]: plain unless a test says
/// otherwise, so a unit test never decorates because `cargo test` happens to
/// run in a terminal.
#[cfg(test)]
pub(crate) mod fake {
	use std::cell::Cell;

	use super::Decor;

	thread_local! {
		static STDOUT: Cell<Option<Decor>> = const { Cell::new(None) };
		static STDERR: Cell<Option<Decor>> = const { Cell::new(None) };
	}

	/// The test build's stdout decoration.
	pub(crate) fn stdout(json: bool) -> Option<Decor> {
		STDOUT.with(Cell::get).filter(|_| !json)
	}

	/// The test build's stderr decoration.
	pub(crate) fn stderr(json: bool) -> Option<Decor> {
		STDERR.with(Cell::get).filter(|_| !json)
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
