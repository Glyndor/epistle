//! Live progress for the long commands, on stderr.
//!
//! A step is drawn as one row that a spinner keeps redrawing with the
//! elapsed time; when the step ends the row is printed once more with ✔ or
//! ✘ and becomes ordinary scrollback. The command ends with a row of its own
//! carrying the total time. Off a terminal (and with `NO_COLOR`, `TERM=dumb`
//! or `--json`) every call does nothing, so a log or a pipe reads exactly
//! what it read before.
//!
//! Every redraw measures the terminal again and cuts the row to it, because
//! a row that wraps leaves its tail behind on the next redraw. Anything else
//! written to the terminal while a row is drawn goes through [`quiet`], which
//! erases the row first; `style::error` and `style::warn` do that already.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anstyle::Style;

use super::cursor::HiddenCursor;
use super::{Decor, Tone, columns, elapsed, fit, paint, width_of};

/// How often the spinner advances.
pub(crate) const TICK: Duration = Duration::from_millis(80);

/// The spinner frames: ten braille cells, the same podup draws.
pub(crate) const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Back to column 0 and erase the row.
pub(crate) const CLEAR_LINE: &str = "\r\x1b[2K";

/// What stands in front of a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
	/// A step in flight, at this spinner frame.
	Frame(usize),
	/// A step or a command that finished.
	Done,
	/// A step or a command that failed.
	Failed,
}

/// One row: ` ✔ label  1.2s`. The label is padded to `label_width` so the
/// times of a command's rows line up, and cut with an ellipsis when the row
/// would not fit `decor.width`; the mark and the time are never cut.
pub(crate) fn row(
	mark: Mark,
	label: &str,
	label_width: usize,
	took: Duration,
	decor: Decor,
) -> String {
	let time = elapsed(took);
	let (glyph, style) = match mark {
		Mark::Frame(frame) => (SPINNER[frame % SPINNER.len()], Style::new()),
		Mark::Done => (Tone::Good.mark(), Tone::Good.style()),
		Mark::Failed => (Tone::Bad.mark(), Tone::Bad.style()),
	};
	// One space, the mark, one space, the label, two spaces, the time.
	let fixed = 3 + 2 + columns(&time);
	let room = decor.width.saturating_sub(fixed);
	let label = if columns(label) > room {
		fit(label, room)
	} else {
		let fill = label_width.min(room).saturating_sub(columns(label));
		format!("{label}{}", " ".repeat(fill))
	};
	format!(
		" {} {label}  {}",
		paint(style, glyph, decor.colour),
		paint(Style::new().dimmed(), &time, decor.colour)
	)
}

/// The step being drawn and where its row stands.
struct Board {
	out: Box<dyn Write + Send>,
	fd: libc::c_int,
	colour: bool,
	label_width: usize,
	step: Option<(String, Instant)>,
	frame: usize,
	drawn: bool,
}

impl Board {
	/// The decoration for this redraw, with the width measured now.
	fn decor(&self) -> Decor {
		Decor {
			colour: self.colour,
			width: width_of(self.fd),
		}
	}

	/// Redraw the step in flight with the next spinner frame.
	fn draw(&mut self) {
		let Some((label, since)) = &self.step else {
			return;
		};
		let line = row(
			Mark::Frame(self.frame),
			label,
			self.label_width,
			since.elapsed(),
			self.decor(),
		);
		self.frame = self.frame.wrapping_add(1);
		let _ = write!(self.out, "{CLEAR_LINE}{line}");
		let _ = self.out.flush();
		self.drawn = true;
	}

	/// Erase the spinner row, if one is on screen.
	fn erase(&mut self) {
		if self.drawn {
			let _ = write!(self.out, "{CLEAR_LINE}");
			let _ = self.out.flush();
			self.drawn = false;
		}
	}

	/// End the step in flight: a permanent row with `mark`, or none.
	fn end(&mut self, mark: Option<Mark>) {
		self.erase();
		if let (Some((label, since)), Some(mark)) = (self.step.take(), mark) {
			let line = row(
				mark,
				&label,
				self.label_width,
				since.elapsed(),
				self.decor(),
			);
			let _ = writeln!(self.out, "{line}");
			let _ = self.out.flush();
		}
	}
}

/// The board shared with the redraw thread and with [`quiet`].
struct Shared {
	board: Mutex<Board>,
	stop: AtomicBool,
}

impl Shared {
	fn board(&self) -> MutexGuard<'_, Board> {
		self.board.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

/// Set while a board is registered, so [`quiet`] takes no lock at all
/// when nothing is drawing (the common case, and every test that forks).
static LIVE: AtomicBool = AtomicBool::new(false);

/// The board [`quiet`] erases before a write.
static CURRENT: Mutex<Option<Arc<Shared>>> = Mutex::new(None);

thread_local! {
	/// Inside [`quiet`] on this thread: a nested call runs its body as is.
	static QUIETING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn current() -> MutexGuard<'static, Option<Arc<Shared>>> {
	CURRENT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The live rows of one command. Inert when stderr is not decorated.
pub(crate) struct Steps {
	shared: Option<Arc<Shared>>,
	ticker: Option<JoinHandle<()>>,
	cursor: Option<HiddenCursor>,
	started: Instant,
}

impl Steps {
	/// The rows for a command whose steps are `labels`, on stderr when it
	/// is decorated (`json` turns them off).
	pub(crate) fn start(labels: &[&str], json: bool) -> Self {
		match super::stderr(json) {
			Some(decor) => Self::on(
				Box::new(std::io::stderr()),
				libc::STDERR_FILENO,
				decor,
				labels,
			),
			None => Self::off(),
		}
	}

	/// Rows that are never drawn, for a run that only lists what it would
	/// do.
	pub(crate) fn off() -> Self {
		Steps {
			shared: None,
			ticker: None,
			cursor: None,
			started: Instant::now(),
		}
	}

	/// The rows drawn on `out`, the terminal whose descriptor is `fd`. The
	/// width is measured on `fd` at every redraw; `decor` gives the colour.
	pub(crate) fn on(
		out: Box<dyn Write + Send>,
		fd: libc::c_int,
		decor: Decor,
		labels: &[&str],
	) -> Self {
		let label_width = labels.iter().map(|label| columns(label)).max().unwrap_or(0);
		let shared = Arc::new(Shared {
			board: Mutex::new(Board {
				out,
				fd,
				colour: decor.colour,
				label_width,
				step: None,
				frame: 0,
				drawn: false,
			}),
			stop: AtomicBool::new(false),
		});
		let cursor = HiddenCursor::new(fd);
		*current() = Some(Arc::clone(&shared));
		LIVE.store(true, Ordering::Release);
		let ticking = Arc::clone(&shared);
		let ticker = std::thread::Builder::new()
			.name("spinner".into())
			.spawn(move || {
				while !ticking.stop.load(Ordering::Acquire) {
					std::thread::park_timeout(TICK);
					if !ticking.stop.load(Ordering::Acquire) {
						ticking.board().draw();
					}
				}
			})
			.ok();
		Steps {
			shared: Some(shared),
			ticker,
			cursor,
			started: Instant::now(),
		}
	}

	/// Whether anything is drawn.
	pub(crate) fn is_live(&self) -> bool {
		self.shared.is_some()
	}

	/// Start the step `label`, drawing its first frame at once. A step
	/// still in flight is ended as done.
	pub(crate) fn begin(&mut self, label: &str) {
		if let Some(shared) = &self.shared {
			let mut board = shared.board();
			board.end(Some(Mark::Done));
			board.step = Some((label.to_string(), Instant::now()));
			board.draw();
		}
	}

	/// The step in flight finished: its row stays with ✔.
	pub(crate) fn done(&mut self) {
		self.end(Some(Mark::Done));
	}

	/// The step in flight failed: its row stays with ✘.
	pub(crate) fn fail(&mut self) {
		self.end(Some(Mark::Failed));
	}

	/// Erase the step in flight without leaving a row, for a step whose
	/// result the command prints itself.
	pub(crate) fn clear(&mut self) {
		self.end(None);
	}

	fn end(&mut self, mark: Option<Mark>) {
		if let Some(shared) = &self.shared {
			shared.board().end(mark);
		}
	}

	/// End the command with a row for `summary` and the total time. A step
	/// still in flight is erased: the summary row is its record.
	pub(crate) fn conclude(mut self, ok: bool, summary: &str) {
		self.clear();
		if let Some(shared) = &self.shared {
			let mut board = shared.board();
			let mark = if ok { Mark::Done } else { Mark::Failed };
			let decor = board.decor();
			let line = row(mark, summary, 0, self.started.elapsed(), decor);
			let _ = writeln!(board.out, "{line}");
			let _ = board.out.flush();
		}
	}
}

impl Drop for Steps {
	fn drop(&mut self) {
		let Some(shared) = self.shared.take() else {
			return;
		};
		shared.stop.store(true, Ordering::Release);
		if let Some(ticker) = self.ticker.take() {
			ticker.thread().unpark();
			let _ = ticker.join();
		}
		// A step nobody ended was cut short by an error.
		shared.board().end(Some(Mark::Failed));
		LIVE.store(false, Ordering::Release);
		*current() = None;
		self.cursor = None;
	}
}

/// Whether a spinner is drawing right now.
pub(crate) fn active() -> bool {
	LIVE.load(Ordering::Acquire)
}

/// Run `body`, which writes to the terminal, with the spinner row erased
/// and held still until it returns. The next tick draws it again below
/// whatever `body` wrote.
pub(crate) fn quiet<R>(body: impl FnOnce() -> R) -> R {
	if !active() || QUIETING.with(std::cell::Cell::get) {
		return body();
	}
	let Some(shared) = current().clone() else {
		return body();
	};
	let mut board = shared.board();
	board.erase();
	QUIETING.with(|flag| flag.set(true));
	let value = body();
	QUIETING.with(|flag| flag.set(false));
	drop(board);
	value
}

/// Run a one-step command under a spinner labelled `label`, then print its
/// row with ✔ or ✘ from the exit code and the total time. The command's
/// stdout is handed to `body`; when stdout is the same terminal it is held
/// until the spinner is gone, so the two never share a row.
pub(crate) fn run(
	label: &str,
	json: bool,
	body: impl FnOnce(&mut dyn Write) -> ExitCode,
) -> ExitCode {
	let mut steps = Steps::start(&[label], json);
	if !steps.is_live() {
		return body(&mut std::io::stdout().lock());
	}
	steps.begin(label);
	let code = if std::io::stdout().is_terminal() {
		let mut held = Vec::new();
		let code = body(&mut held);
		steps.clear();
		let mut out = std::io::stdout().lock();
		let _ = out.write_all(&held);
		let _ = out.flush();
		code
	} else {
		body(&mut std::io::stdout().lock())
	};
	steps.conclude(code == ExitCode::SUCCESS, label);
	code
}

#[cfg(test)]
mod tests;
