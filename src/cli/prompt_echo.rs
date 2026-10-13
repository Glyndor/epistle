//! Terminal echo switched off for the length of one secret read.
//!
//! [`EchoOff`] clears `ECHO` on a terminal and puts the saved attributes back
//! when it is dropped. `Drop` does not run when the process is killed by a
//! signal, and Ctrl-C during a password prompt is the common way out: the
//! shell would be left without echo. So while the guard is alive it also
//! installs a handler for SIGINT, SIGTERM and SIGHUP that restores the saved
//! attributes, puts the previous disposition back and raises the signal
//! again, so the process still dies (or the previous handler still runs) the
//! way it would have without the prompt.
//!
//! The handler may only call async-signal-safe functions, so the attributes it
//! restores live in statics written before the handler is installed. Only one
//! guard can be alive at a time; a second one is refused rather than racing
//! the first over those statics.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// The signals that end a prompt from the keyboard (Ctrl-C), from a process
/// manager, or from a closed terminal.
const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// State the signal handler reads. Written only while no handler is
/// installed (before `ARMED` is set), read only by the handler or by the
/// guard that owns it.
struct Saved {
	termios: UnsafeCell<MaybeUninit<libc::termios>>,
	previous: UnsafeCell<[MaybeUninit<libc::sigaction>; 3]>,
}

// SAFETY: access is serialised by `IN_USE` (one guard at a time) and by the
// order of writes: the termios is written before `ARMED` is set and each
// previous action is written by the `sigaction` call that installs our
// handler for that signal, so the handler never reads a slot being written.
unsafe impl Sync for Saved {}

static SAVED: Saved = Saved {
	termios: UnsafeCell::new(MaybeUninit::uninit()),
	previous: UnsafeCell::new([MaybeUninit::uninit(); 3]),
};
static FD: AtomicI32 = AtomicI32::new(-1);
static ARMED: AtomicBool = AtomicBool::new(false);
static IN_USE: AtomicBool = AtomicBool::new(false);

/// Echo is off on `fd` while this value is alive.
#[derive(Debug)]
pub(crate) struct EchoOff {
	fd: libc::c_int,
	saved: libc::termios,
	installed: usize,
}

impl EchoOff {
	/// Turn echo off on `fd`. Fails when `fd` is not a terminal or another
	/// guard is alive; in both cases the terminal is left as it was.
	pub(crate) fn new(fd: libc::c_int) -> Result<Self, String> {
		if IN_USE
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.is_err()
		{
			return Err("another secret prompt is already reading the terminal".to_string());
		}
		let mut state = MaybeUninit::<libc::termios>::uninit();
		// SAFETY: `state` is a valid out pointer for one termios.
		if unsafe { libc::tcgetattr(fd, state.as_mut_ptr()) } != 0 {
			let error = std::io::Error::last_os_error();
			IN_USE.store(false, Ordering::Release);
			return Err(format!("cannot read the terminal attributes: {error}"));
		}
		// SAFETY: tcgetattr returned 0, so it filled `state`.
		let saved = unsafe { state.assume_init() };
		// SAFETY: no handler is installed and `IN_USE` keeps other guards out.
		unsafe { (*SAVED.termios.get()).write(saved) };
		FD.store(fd, Ordering::Release);
		ARMED.store(true, Ordering::Release);
		let mut guard = EchoOff {
			fd,
			saved,
			installed: 0,
		};
		guard.install_handlers();
		let mut quiet = saved;
		quiet.c_lflag &= !libc::ECHO;
		// SAFETY: `quiet` is a valid termios copied from the terminal.
		if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
			let error = std::io::Error::last_os_error();
			drop(guard);
			return Err(format!("cannot turn off terminal echo: {error}"));
		}
		Ok(guard)
	}

	fn install_handlers(&mut self) {
		// SAFETY: a zeroed sigaction is a valid starting value; the mask is
		// then filled and the handler set before it is used.
		let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
		action.sa_sigaction = restore_and_reraise as *const () as libc::sighandler_t;
		// SAFETY: `action.sa_mask` is a valid sigset_t.
		unsafe {
			libc::sigemptyset(&mut action.sa_mask);
			for signal in SIGNALS {
				libc::sigaddset(&mut action.sa_mask, signal);
			}
		}
		for (index, signal) in SIGNALS.into_iter().enumerate() {
			// SAFETY: the previous action is written into its own slot by the
			// same call that installs our handler for that signal.
			let slot = unsafe { (*SAVED.previous.get())[index].as_mut_ptr() };
			if unsafe { libc::sigaction(signal, &action, slot) } != 0 {
				break;
			}
			self.installed = index + 1;
		}
	}
}

impl Drop for EchoOff {
	fn drop(&mut self) {
		// Attributes first: a signal that lands before the handlers are put
		// back restores the same attributes again, which is harmless.
		// SAFETY: `saved` came from tcgetattr on this descriptor.
		unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
		for (index, signal) in SIGNALS.into_iter().enumerate().take(self.installed) {
			// SAFETY: slot `index` was filled when the handler was installed.
			unsafe {
				let previous = (*SAVED.previous.get())[index].as_ptr();
				libc::sigaction(signal, previous, std::ptr::null_mut());
			}
		}
		ARMED.store(false, Ordering::Release);
		FD.store(-1, Ordering::Release);
		IN_USE.store(false, Ordering::Release);
	}
}

/// Signal handler: restore the attributes, put back the disposition that was
/// there before the prompt and raise the signal again. Only async-signal-safe
/// calls (tcsetattr, sigaction, raise).
extern "C" fn restore_and_reraise(signal: libc::c_int) {
	if ARMED.load(Ordering::Acquire) {
		let fd = FD.load(Ordering::Acquire);
		// SAFETY: the termios slot was written before ARMED was set.
		unsafe { libc::tcsetattr(fd, libc::TCSANOW, (*SAVED.termios.get()).as_ptr()) };
	}
	if let Some(index) = SIGNALS.iter().position(|&known| known == signal) {
		// SAFETY: our handler for `signal` is installed, so its slot holds the
		// previous action. The re-raised signal stays pending until this
		// handler returns, then the previous disposition handles it.
		unsafe {
			libc::sigaction(
				signal,
				(*SAVED.previous.get())[index].as_ptr(),
				std::ptr::null_mut(),
			);
			libc::raise(signal);
		}
	}
}
