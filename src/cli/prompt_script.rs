//! Test source for the prompt console.
//!
//! In a test build the prompt entry points take their console from here
//! instead of the process's stdin and stderr. [`scripted`] runs a command
//! handler against a console the test describes (interactive or not, a pty
//! or no terminal, the operator's typed answers) and returns what the
//! handler wrote to stderr. With no script set, the console is the one a
//! piped run sees: not interactive, no terminal, empty input. That keeps a
//! test from blocking on the developer's terminal when `cargo test` runs in
//! one.

use std::cell::RefCell;
use std::io::Cursor;

use super::{Console, Input};

struct Script {
	interactive: bool,
	tty: Option<libc::c_int>,
	input: Cursor<Vec<u8>>,
	err: anstream::AutoStream<Vec<u8>>,
}

thread_local! {
	static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
}

/// What a scripted run left behind.
pub(crate) struct Run<R> {
	/// The handler's return value.
	pub(crate) value: R,
	/// Everything written to stderr through the console, colour codes
	/// stripped.
	pub(crate) stderr: String,
	/// Bytes of the typed answers nobody read.
	pub(crate) unread: usize,
}

/// Run `body` with prompts answered from `typed`. `interactive` is whether
/// a terminal is attached; `tty` is the terminal whose echo a secret read
/// turns off.
pub(crate) fn scripted<R>(
	interactive: bool,
	tty: Option<libc::c_int>,
	typed: impl AsRef<[u8]>,
	body: impl FnOnce() -> R,
) -> Run<R> {
	let typed = typed.as_ref();
	let script = Script {
		interactive,
		tty,
		input: Cursor::new(typed.to_vec()),
		err: anstream::AutoStream::new(Vec::new(), anstream::ColorChoice::Never),
	};
	SCRIPT.with(|slot| *slot.borrow_mut() = Some(script));
	let value = body();
	let script = SCRIPT
		.with(|slot| slot.borrow_mut().take())
		.expect("script still set");
	let unread = typed.len() - script.input.position() as usize;
	let stderr = String::from_utf8(script.err.into_inner()).expect("stderr is UTF-8");
	Run {
		value,
		stderr,
		unread,
	}
}

/// The test build's stdin: whatever the script has not read yet, handed
/// over (and counted as read) when a handler asks for its reader.
pub(crate) fn stdin() -> Cursor<Vec<u8>> {
	SCRIPT.with(|slot| match slot.borrow_mut().as_mut() {
		Some(script) => {
			let start = script.input.position() as usize;
			let rest = script.input.get_ref()[start..].to_vec();
			script
				.input
				.set_position(script.input.get_ref().len() as u64);
			Cursor::new(rest)
		}
		None => Cursor::new(Vec::new()),
	})
}

/// The test build's console source; see the module docs.
pub(super) fn with_console<R>(input: Input<'_>, body: impl FnOnce(&mut Console<'_>) -> R) -> R {
	SCRIPT.with(|slot| {
		let mut slot = slot.borrow_mut();
		let Some(script) = slot.as_mut() else {
			let mut empty = Cursor::new(Vec::new());
			return body(&mut Console {
				interactive: false,
				tty: None,
				input: match input {
					Input::Reader(reader) => reader,
					Input::Stdin | Input::Terminal => &mut empty,
				},
				err: &mut crate::cli::style::stderr(),
			});
		};
		body(&mut Console {
			interactive: script.interactive,
			tty: script.tty,
			input: match input {
				Input::Reader(reader) => reader,
				Input::Stdin | Input::Terminal => &mut script.input,
			},
			err: &mut script.err,
		})
	})
}

/// A pseudo-terminal for tests that read a secret with echo off. Holding
/// it also holds the lock that keeps two tests from turning echo off at
/// once: only one echo guard may be alive in the process.
#[cfg(unix)]
pub(crate) struct Pty {
	pub(crate) slave: libc::c_int,
	master: libc::c_int,
	_turn: std::sync::MutexGuard<'static, ()>,
}

#[cfg(unix)]
impl Pty {
	pub(crate) fn open() -> Self {
		static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
		let turn = TURN
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let (mut master, mut slave) = (-1, -1);
		// SAFETY: both out pointers are valid; name, termios and winsize may
		// be null.
		let rc = unsafe {
			libc::openpty(
				&mut master,
				&mut slave,
				std::ptr::null_mut(),
				std::ptr::null(),
				std::ptr::null(),
			)
		};
		assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
		let pty = Pty {
			slave,
			master,
			_turn: turn,
		};
		assert!(pty.echo_on(), "a fresh pty echoes");
		pty
	}

	/// Type `text` on the terminal, as the operator would.
	pub(crate) fn type_in(&self, text: &str) {
		// SAFETY: the buffer is valid for its length and the master is ours.
		let written = unsafe { libc::write(self.master, text.as_ptr().cast(), text.len()) };
		assert_eq!(written, text.len() as isize, "typing on the pty");
	}

	/// Whether the terminal echoes typed input right now.
	pub(crate) fn echo_on(&self) -> bool {
		let mut state = std::mem::MaybeUninit::<libc::termios>::uninit();
		// SAFETY: valid out pointer; checked below.
		let rc = unsafe { libc::tcgetattr(self.slave, state.as_mut_ptr()) };
		assert_eq!(rc, 0, "tcgetattr: {}", std::io::Error::last_os_error());
		// SAFETY: tcgetattr succeeded.
		unsafe { state.assume_init() }.c_lflag & libc::ECHO != 0
	}
}

#[cfg(unix)]
impl Drop for Pty {
	fn drop(&mut self) {
		// SAFETY: both descriptors were opened by openpty and are closed once.
		unsafe {
			libc::close(self.slave);
			libc::close(self.master);
		}
	}
}
