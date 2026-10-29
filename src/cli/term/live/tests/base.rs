//! The spinner: the row it draws at 40 and 120 columns, with and without
//! colour; nothing at all off a terminal; and against a real pseudo-terminal,
//! a run that ends with ✔ and gives the cursor back, including when Ctrl-C
//! ends the process in the middle of a step.

use std::io::Read;
use std::os::fd::FromRawFd;
use std::time::Duration;

use super::*;
use crate::cli::term::cursor::{HIDE, SHOW};
use crate::cli::term::table::tests::base::visible;

#[test]
fn a_row_carries_the_mark_the_label_and_the_time() {
	let plain = Decor {
		colour: false,
		width: 120,
	};
	assert_eq!(
		row(Mark::Done, "archive", 8, Duration::from_millis(1200), plain),
		" ✔ archive   1.2s"
	);
	assert_eq!(
		row(
			Mark::Failed,
			"database",
			8,
			Duration::from_millis(300),
			plain
		),
		" ✘ database  0.3s"
	);
	assert_eq!(
		row(Mark::Frame(0), "files", 8, Duration::from_millis(50), plain),
		" ⠋ files     0.1s"
	);
	let coloured = row(
		Mark::Done,
		"archive",
		8,
		Duration::from_millis(1200),
		Decor::coloured(120),
	);
	assert!(coloured.contains("\x1b[32m✔\x1b[0m"), "{coloured:?}");
	assert!(
		coloured.contains("\x1b[2m1.2s\x1b[0m"),
		"the time is dim: {coloured:?}"
	);
	assert_eq!(visible(&coloured), " ✔ archive   1.2s");
}

#[test]
fn a_long_label_is_cut_so_the_row_fits_forty_columns() {
	let label = "checking every record of a-very-long-domain-name.example.org";
	for colour in [false, true] {
		let line = row(
			Mark::Frame(3),
			label,
			label.len(),
			Duration::from_secs(75),
			Decor { colour, width: 40 },
		);
		let seen = visible(&line);
		assert_eq!(seen.chars().count(), 40, "{seen:?}");
		assert!(seen.contains('…'), "{seen:?}");
		assert!(
			seen.ends_with("1m15s"),
			"the time survives the cut: {seen:?}"
		);
	}
}

#[test]
fn off_a_terminal_every_call_is_silent() {
	let _turn = turn();
	let mut steps = Steps::start(&["archive", "files"], false);
	assert!(!steps.is_live());
	steps.begin("archive");
	steps.done();
	steps.begin("files");
	steps.fail();
	steps.conclude(true, "restore");
	assert!(!active());
}

/// A pseudo-terminal of `columns` columns, read from its master side.
struct Pty {
	master: libc::c_int,
	slave: libc::c_int,
}

impl Pty {
	fn open(columns: u16) -> Self {
		let size = libc::winsize {
			ws_row: 24,
			ws_col: columns,
			ws_xpixel: 0,
			ws_ypixel: 0,
		};
		let (mut master, mut slave) = (-1, -1);
		// SAFETY: both out pointers are valid; the name may be null.
		let rc = unsafe {
			libc::openpty(
				&mut master,
				&mut slave,
				std::ptr::null_mut(),
				std::ptr::null(),
				&size,
			)
		};
		assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
		Pty { master, slave }
	}

	/// A writer on the slave side, as stderr would be.
	fn writer(&self) -> Box<dyn Write + Send> {
		// SAFETY: dup returns a fresh descriptor the File then owns.
		let fd = unsafe { libc::dup(self.slave) };
		assert!(fd >= 0);
		Box::new(unsafe { std::fs::File::from_raw_fd(fd) })
	}

	/// Everything written to the slave so far.
	fn drain(&self) -> String {
		// SAFETY: the master is ours; O_NONBLOCK stops the read at the end.
		unsafe {
			let flags = libc::fcntl(self.master, libc::F_GETFL);
			libc::fcntl(self.master, libc::F_SETFL, flags | libc::O_NONBLOCK);
		}
		// SAFETY: dup returns a fresh descriptor the File then owns.
		let mut file = unsafe { std::fs::File::from_raw_fd(libc::dup(self.master)) };
		let mut bytes = Vec::new();
		let mut chunk = [0u8; 4096];
		loop {
			match file.read(&mut chunk) {
				Ok(0) | Err(_) => break,
				Ok(n) => bytes.extend_from_slice(&chunk[..n]),
			}
		}
		String::from_utf8_lossy(&bytes).into_owned()
	}
}

impl Drop for Pty {
	fn drop(&mut self) {
		// SAFETY: both descriptors were opened by openpty and are closed once.
		unsafe {
			libc::close(self.slave);
			libc::close(self.master);
		}
	}
}

/// One spinner test at a time: the cursor guard is process-wide.
static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn turn() -> std::sync::MutexGuard<'static, ()> {
	TURN.lock()
		.unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn on_a_pty_the_steps_spin_then_finish_with_a_mark_and_the_cursor_comes_back() {
	let _turn = turn();
	let pty = Pty::open(120);
	let mut steps = Steps::on(
		pty.writer(),
		pty.slave,
		Decor::coloured(120),
		&["archive", "files"],
	);
	assert!(steps.is_live());
	steps.begin("archive");
	std::thread::sleep(TICK * 3);
	steps.done();
	steps.begin("files");
	steps.fail();
	steps.conclude(false, "restore");
	let screen = pty.drain();
	let hide = screen.find(HIDE).expect("the cursor is hidden");
	let spin = screen.find("archive").expect("the spinner drew the step");
	let show = screen.rfind(SHOW).expect("the cursor is shown again");
	assert!(hide < spin && spin < show, "{screen:?}");
	assert!(
		SPINNER
			.iter()
			.any(|frame| screen.contains(&format!("{frame} archive"))),
		"a spinner frame: {screen:?}"
	);
	let seen = visible(&screen);
	assert!(seen.contains(" ✔ archive"), "{seen:?}");
	assert!(seen.contains(" ✘ files"), "{seen:?}");
	assert!(seen.contains(" ✘ restore"), "{seen:?}");
	assert!(
		screen.trim_end().ends_with(SHOW),
		"nothing is drawn after the cursor comes back: {screen:?}"
	);
	assert!(!active(), "the board is gone");
}

#[test]
fn on_a_narrow_pty_no_row_is_wider_than_the_terminal() {
	let _turn = turn();
	let pty = Pty::open(30);
	let label = "a-step-label-much-longer-than-thirty-columns";
	let mut steps = Steps::on(pty.writer(), pty.slave, Decor::coloured(120), &[label]);
	steps.begin(label);
	std::thread::sleep(TICK * 3);
	steps.done();
	drop(steps);
	let screen = visible(&pty.drain());
	for line in screen.split(['\r', '\n']) {
		assert!(line.chars().count() <= 30, "{line:?} in {screen:?}");
	}
	assert!(screen.contains('…'), "{screen:?}");
}

#[test]
fn a_message_written_quietly_starts_on_a_clean_line() {
	let _turn = turn();
	let pty = Pty::open(120);
	let mut steps = Steps::on(pty.writer(), pty.slave, Decor::coloured(120), &["files"]);
	steps.begin("files");
	std::thread::sleep(TICK * 3);
	quiet(|| {
		let mut out = pty.writer();
		let _ = out.write_all(b"warning: hello\n");
	});
	steps.done();
	drop(steps);
	let screen = pty.drain();
	let warning = screen.find("warning: hello").expect("the warning");
	assert!(
		screen[..warning].ends_with(CLEAR_LINE),
		"the spinner row is erased before the warning: {screen:?}"
	);
}

#[test]
fn ctrl_c_in_the_middle_of_a_step_gives_the_cursor_back_before_the_process_dies() {
	let _turn = turn();
	let pty = Pty::open(80);
	// SAFETY: the child only draws through the spinner, raises SIGINT and
	// leaves with `_exit`, so it never returns into the test harness.
	let pid = unsafe { libc::fork() };
	assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
	if pid == 0 {
		unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
		let mut steps = Steps::on(pty.writer(), pty.slave, Decor::coloured(80), &["database"]);
		steps.begin("database");
		std::thread::sleep(TICK * 2);
		unsafe { libc::raise(libc::SIGINT) };
		std::mem::forget(steps);
		unsafe { libc::_exit(5) };
	}
	let mut status = 0;
	// SAFETY: `pid` is our child; `status` is a valid out pointer.
	let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
	assert_eq!(waited, pid);
	assert!(
		libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGINT,
		"the child must die of SIGINT (status {status:#x})"
	);
	let screen = pty.drain();
	let hide = screen.find(HIDE).expect("hidden");
	let show = screen.rfind(SHOW).expect("SIGINT left the cursor hidden");
	assert!(hide < show, "{screen:?}");
}
