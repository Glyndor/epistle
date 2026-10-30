//! Termination signals held off while a restore writes.
//!
//! A restore loads the database first and lays the mail files down after.
//! `psql` runs inside the `db` container, outside this process group, so a
//! signal that ended `epistle` half way did not stop the load. On the Debian 13
//! VM a SIGTERM sent to the process group of `epistle restore --force` 0.5 s in
//! left the database restored, the files not, and the staged copy of the dump
//! on the host and in the container (#1331).
//!
//! While a [`HeldSignals`] is alive, SIGINT, SIGTERM and SIGHUP only record
//! that they came. The restore asks [`stop_if_arrived`] before each step that
//! would start writing: a signal that came before the load began stops the
//! restore there, after its cleanup, and one that came later lets it finish, so
//! the database and the files end up from the same archive. When the guard is
//! dropped the previous dispositions come back and the signal is raised again,
//! so the process still ends the way it was asked to, only later.
//!
//! Commands spawned while the guard is alive go into a process group of their
//! own ([`spawn_apart`]): a signal sent to the restore's group, or Ctrl-C at
//! its terminal, must not end the `podup` call that is waiting for `psql`,
//! since the restore would then lose the answer of a load that goes on.
//!
//! The handler only calls async-signal-safe functions (an atomic store and
//! `write`). One guard is alive at a time; a second one is refused.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use super::db_dump::BackupError;

/// The signals that end a command from the keyboard, from a process manager,
/// or from a closed terminal.
const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// What the handler writes to stderr when the first signal comes, so the
/// operator knows why the command did not stop at once.
const NOTE: &[u8] = b"epistle: a stop signal arrived; the restore stops at the next safe point, so the database and the files end up both restored or both as they were\n";

/// The dispositions in place before the guard installed its handler.
struct Previous(UnsafeCell<[MaybeUninit<libc::sigaction>; 3]>);

// SAFETY: a slot is written only by the `sigaction` call that installs the
// handler for its signal, while `HELD` keeps every other guard out, and read
// only by the guard that owns it.
unsafe impl Sync for Previous {}

static PREVIOUS: Previous = Previous(UnsafeCell::new([MaybeUninit::uninit(); 3]));
static ARRIVED: AtomicI32 = AtomicI32::new(0);
static HELD: AtomicBool = AtomicBool::new(false);

/// SIGINT, SIGTERM and SIGHUP are recorded, not acted on, while this value
/// is alive. Dropping it puts the previous dispositions back and raises the
/// first signal that came, if one did.
#[derive(Debug)]
pub(in crate::cli::backup) struct HeldSignals {
	/// Bit `i` is set when the handler for `SIGNALS[i]` is installed.
	installed: u8,
}

impl HeldSignals {
	/// Hold the three signals. `None` when another guard is alive. A signal
	/// the process ignores (`nohup` ignores SIGHUP) stays ignored.
	pub(in crate::cli::backup) fn hold() -> Option<Self> {
		if HELD
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.is_err()
		{
			return None;
		}
		ARRIVED.store(0, Ordering::Release);
		// SAFETY: a zeroed sigaction is a valid starting value; the mask and
		// the handler are set before it is used.
		let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
		action.sa_sigaction = note_arrival as *const () as libc::sighandler_t;
		action.sa_flags = libc::SA_RESTART;
		// SAFETY: `action.sa_mask` is a valid sigset_t.
		unsafe {
			libc::sigemptyset(&mut action.sa_mask);
			for signal in SIGNALS {
				libc::sigaddset(&mut action.sa_mask, signal);
			}
		}
		let mut guard = HeldSignals { installed: 0 };
		for (index, signal) in SIGNALS.into_iter().enumerate() {
			// SAFETY: the slot of this signal is written by this call alone.
			let slot = unsafe { (*PREVIOUS.0.get())[index].as_mut_ptr() };
			// SAFETY: reading the current disposition into a valid slot.
			if unsafe { libc::sigaction(signal, std::ptr::null(), slot) } != 0 {
				continue;
			}
			// SAFETY: the read above filled the slot.
			if unsafe { (*slot).sa_sigaction } == libc::SIG_IGN {
				continue;
			}
			// SAFETY: `action` is fully initialised; the previous action is
			// already in the slot.
			if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0 {
				guard.installed |= 1 << index;
			}
		}
		Some(guard)
	}
}

impl Drop for HeldSignals {
	fn drop(&mut self) {
		for (index, signal) in SIGNALS.into_iter().enumerate() {
			if self.installed & (1 << index) != 0 {
				// SAFETY: slot `index` was filled before its handler went in.
				unsafe {
					libc::sigaction(
						signal,
						(*PREVIOUS.0.get())[index].as_ptr(),
						std::ptr::null_mut(),
					);
				}
			}
		}
		let signal = ARRIVED.swap(0, Ordering::AcqRel);
		HELD.store(false, Ordering::Release);
		if signal != 0 {
			// SAFETY: raise only sends a signal to this thread; the previous
			// disposition, now back in place, decides what it does.
			unsafe { libc::raise(signal) };
		}
	}
}

/// Signal handler: keep the first signal and say once that it was seen.
/// Only async-signal-safe calls (an atomic exchange and `write`).
extern "C" fn note_arrival(signal: libc::c_int) {
	if ARRIVED
		.compare_exchange(0, signal, Ordering::AcqRel, Ordering::Acquire)
		.is_ok()
	{
		// SAFETY: `NOTE` is a valid buffer of the given length.
		let _ = unsafe { libc::write(2, NOTE.as_ptr().cast(), NOTE.len()) };
	}
}

/// `Err(BackupError::Interrupted)` when a held signal has come: the caller
/// stops before its next write and cleans up what it staged.
pub(in crate::cli::backup) fn stop_if_arrived() -> Result<(), BackupError> {
	match ARRIVED.load(Ordering::Acquire) {
		0 => Ok(()),
		signal => Err(BackupError::Interrupted(signal)),
	}
}

/// Whether a command spawned now goes into a process group of its own: true
/// while a guard is alive.
pub(in crate::cli::backup) fn spawn_apart() -> bool {
	HELD.load(Ordering::Acquire)
}

/// The usual name of one of the held signals, for messages.
pub(in crate::cli::backup) fn signal_name(signal: libc::c_int) -> String {
	match signal {
		libc::SIGINT => "SIGINT".to_string(),
		libc::SIGTERM => "SIGTERM".to_string(),
		libc::SIGHUP => "SIGHUP".to_string(),
		other => format!("signal {other}"),
	}
}
