//! The terminal cursor hidden while a spinner redraws its row.
//!
//! [`HiddenCursor`] hides the cursor and shows it again when it is dropped.
//! `Drop` does not run when a signal ends the process, and Ctrl-C in the
//! middle of a backup is the usual way to stop one, so while the guard is
//! alive a handler for SIGINT, SIGTERM and SIGHUP writes the show sequence,
//! puts the previous disposition back and raises the signal again. The
//! process then dies (or the previous handler runs) the way it would have
//! without the spinner. The same shape as the echo guard in the prompt
//! module, which this one chains to when both are installed.
//!
//! The handler may only call async-signal-safe functions: `write` on a
//! descriptor kept in a static, `sigaction` and `raise`. One guard is alive
//! at a time; a second one is refused rather than racing over the statics.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Hide the cursor (DECTCEM off).
pub(crate) const HIDE: &str = "\x1b[?25l";

/// Show the cursor (DECTCEM on).
pub(crate) const SHOW: &str = "\x1b[?25h";

/// The signals that end a long command from the keyboard (Ctrl-C), from a
/// process manager, or from a closed terminal.
const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The dispositions in place before the guard installed its handler.
struct Previous(UnsafeCell<[MaybeUninit<libc::sigaction>; 3]>);

// SAFETY: written only by the `sigaction` call that installs the handler for
// that slot's signal, while `IN_USE` keeps every other guard out; read only by
// that handler or by the guard that owns it.
unsafe impl Sync for Previous {}

static PREVIOUS: Previous = Previous(UnsafeCell::new([MaybeUninit::uninit(); 3]));
static FD: AtomicI32 = AtomicI32::new(-1);
static IN_USE: AtomicBool = AtomicBool::new(false);

/// The cursor is hidden on a descriptor while this value is alive.
#[derive(Debug)]
pub(crate) struct HiddenCursor {
	fd: libc::c_int,
	installed: usize,
}

impl HiddenCursor {
	/// Hide the cursor on `fd`. `None` when another guard is alive, in
	/// which case the cursor is left alone and the caller redraws with it
	/// visible.
	pub(crate) fn new(fd: libc::c_int) -> Option<Self> {
		if IN_USE
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.is_err()
		{
			return None;
		}
		FD.store(fd, Ordering::Release);
		let mut guard = HiddenCursor { fd, installed: 0 };
		guard.install_handlers();
		write_all(fd, HIDE);
		Some(guard)
	}

	fn install_handlers(&mut self) {
		// SAFETY: a zeroed sigaction is a valid starting value; the mask is
		// filled and the handler set before it is used.
		let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
		action.sa_sigaction = show_and_reraise as *const () as libc::sighandler_t;
		// SAFETY: `action.sa_mask` is a valid sigset_t.
		unsafe {
			libc::sigemptyset(&mut action.sa_mask);
			for signal in SIGNALS {
				libc::sigaddset(&mut action.sa_mask, signal);
			}
		}
		for (index, signal) in SIGNALS.into_iter().enumerate() {
			// SAFETY: the previous action is written into its own slot by the
			// same call that installs the handler for that signal.
			let slot = unsafe { (*PREVIOUS.0.get())[index].as_mut_ptr() };
			if unsafe { libc::sigaction(signal, &action, slot) } != 0 {
				break;
			}
			self.installed = index + 1;
		}
	}
}

impl Drop for HiddenCursor {
	fn drop(&mut self) {
		write_all(self.fd, SHOW);
		for (index, signal) in SIGNALS.into_iter().enumerate().take(self.installed) {
			// SAFETY: slot `index` was filled when the handler was installed.
			unsafe {
				let previous = (*PREVIOUS.0.get())[index].as_ptr();
				libc::sigaction(signal, previous, std::ptr::null_mut());
			}
		}
		FD.store(-1, Ordering::Release);
		IN_USE.store(false, Ordering::Release);
	}
}

/// `write(2)` until `text` is out or the descriptor refuses. Used from the
/// signal handler, so nothing here allocates.
fn write_all(fd: libc::c_int, text: &str) {
	let mut bytes = text.as_bytes();
	while !bytes.is_empty() {
		// SAFETY: `bytes` is a valid buffer of the given length.
		let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
		if written <= 0 {
			return;
		}
		bytes = &bytes[written as usize..];
	}
}

/// Signal handler: show the cursor, put back the disposition that was there
/// before the spinner and raise the signal again. Only async-signal-safe
/// calls (write, sigaction, raise).
extern "C" fn show_and_reraise(signal: libc::c_int) {
	let fd = FD.load(Ordering::Acquire);
	if fd >= 0 {
		// Erase the spinner row first, so the shell prompt starts on a
		// clean line.
		write_all(fd, "\r\x1b[2K");
		write_all(fd, SHOW);
	}
	if let Some(index) = SIGNALS.iter().position(|&known| known == signal) {
		// SAFETY: the handler for `signal` is installed, so its slot holds the
		// previous action. The re-raised signal stays pending until this
		// handler returns, then the previous disposition handles it.
		unsafe {
			libc::sigaction(
				signal,
				(*PREVIOUS.0.get())[index].as_ptr(),
				std::ptr::null_mut(),
			);
			libc::raise(signal);
		}
	}
}
