//! Relaying stop signals to the command run for the service account.
//!
//! The delegating root process waits for the account's command. A SIGTERM,
//! SIGINT or SIGHUP aimed at its process group (a process manager stopping the
//! unit, Ctrl-C, a closed terminal) reaches that command directly, since it is
//! a child in the same group, and it would end the waiting process by the
//! default action, leaving the command running on its own with nobody to
//! report its exit status (#1342). While a [`Relay`] is alive the three
//! signals are relayed to the command instead: a signal sent only to this
//! process reaches it too, one sent to the whole group reaches it twice, and
//! a command that keeps the first signal and acts on it later, like a restore
//! holding the signals until its next safe point, takes the second as a no-op.
//! This process never ends the command, never escalates and never gives up
//! waiting: the grace period belongs to the command.
//!
//! The handler only calls async-signal-safe functions (atomics and `kill`).

use std::cell::UnsafeCell;
use std::io;
use std::mem::MaybeUninit;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// The signals that end a command from the keyboard, a process manager or a
/// closed terminal.
const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The dispositions in place before the relay installed its handler.
struct Previous(UnsafeCell<[MaybeUninit<libc::sigaction>; 3]>);

// SAFETY: a slot is written only by the `sigaction` call that installs the
// handler for its signal, while `HELD` keeps every other relay out, and read
// only by the relay that owns it.
unsafe impl Sync for Previous {}

static PREVIOUS: Previous = Previous(UnsafeCell::new([MaybeUninit::uninit(); 3]));
/// The command's pid, or 0 while there is none.
static CHILD: AtomicI32 = AtomicI32::new(0);
/// The first signal that came before the command had a pid.
static EARLY: AtomicI32 = AtomicI32::new(0);
static HELD: AtomicBool = AtomicBool::new(false);
/// How many handler calls are between reading `CHILD` and sending the signal.
static ACTIVE: AtomicI32 = AtomicI32::new(0);

/// Relays SIGINT, SIGTERM and SIGHUP to the command while it is alive; the
/// previous dispositions come back when it is dropped.
struct Relay {
	/// Bit `i` is set when the handler for `SIGNALS[i]` is installed.
	installed: u8,
}

impl Relay {
	/// Install the handler. `None` when another relay is alive. A signal the
	/// process ignores (`nohup` ignores SIGHUP) stays ignored.
	fn install() -> Option<Self> {
		if HELD
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.is_err()
		{
			return None;
		}
		CHILD.store(0, Ordering::Release);
		EARLY.store(0, Ordering::Release);
		// SAFETY: a zeroed sigaction is a valid starting value; the mask and
		// the handler are set before it is used.
		let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
		action.sa_sigaction = relay as *const () as libc::sighandler_t;
		action.sa_flags = libc::SA_RESTART;
		// SAFETY: `action.sa_mask` is a valid sigset_t.
		unsafe {
			libc::sigemptyset(&mut action.sa_mask);
			for signal in SIGNALS {
				libc::sigaddset(&mut action.sa_mask, signal);
			}
		}
		let mut relay = Relay { installed: 0 };
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
			// SAFETY: `action` is fully initialised.
			if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0 {
				relay.installed |= 1 << index;
			}
		}
		Some(relay)
	}

	/// Tell the handler where the command is, and pass on a signal that came
	/// while it was being started.
	fn attach(&self, pid: libc::pid_t) {
		CHILD.store(pid, Ordering::Release);
		let early = EARLY.swap(0, Ordering::AcqRel);
		if early != 0 {
			// SAFETY: kill only sends a signal to the child just spawned.
			unsafe { libc::kill(pid, early) };
		}
	}
}

impl Drop for Relay {
	fn drop(&mut self) {
		CHILD.store(0, Ordering::Release);
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
		HELD.store(false, Ordering::Release);
	}
}

/// Signal handler: pass the signal to the command, or keep the first one
/// until there is a command. Only async-signal-safe calls.
extern "C" fn relay(signal: libc::c_int) {
	ACTIVE.fetch_add(1, Ordering::SeqCst);
	let pid = CHILD.load(Ordering::SeqCst);
	if pid > 0 {
		// SAFETY: kill only sends a signal; `pid` is the child being waited
		// for, and it is not reaped while `ACTIVE` is above zero.
		unsafe { libc::kill(pid, signal) };
	} else {
		let _ = EARLY.compare_exchange(0, signal, Ordering::AcqRel, Ordering::Acquire);
	}
	ACTIVE.fetch_sub(1, Ordering::SeqCst);
}

/// Wait until the child `pid` has ended without reaping it, so its pid stays
/// taken and no signal can reach a process that reused it.
fn wait_for_exit(pid: libc::pid_t) -> io::Result<()> {
	loop {
		// SAFETY: a zeroed siginfo is valid storage for waitid's answer.
		let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
		// SAFETY: `info` outlives the call; WNOWAIT leaves the child to reap.
		let rc = unsafe {
			libc::waitid(
				libc::P_PID,
				pid as libc::id_t,
				&mut info,
				libc::WEXITED | libc::WNOWAIT,
			)
		};
		if rc == 0 {
			return Ok(());
		}
		let error = io::Error::last_os_error();
		if error.kind() != io::ErrorKind::Interrupted {
			return Err(error);
		}
	}
}

/// Run `command` and wait for it, relaying the stop signals to it meanwhile.
/// The command is not ended from here whatever it takes to finish.
pub(super) fn run(command: &mut Command) -> io::Result<ExitStatus> {
	run_with(command, |_| {})
}

/// [`run`], calling `ended` once the command has ended but is not yet reaped
/// and nothing can signal it any more.
///
/// The order is the point: wait without reaping, stop the handler from
/// signalling the pid and wait for a handler already on its way, and only then
/// reap. Reaping first frees the pid, and a signal sent to it afterwards could
/// land on an unrelated process that was given the number.
fn run_with(command: &mut Command, ended: impl FnOnce(libc::pid_t)) -> io::Result<ExitStatus> {
	let relay = Relay::install();
	let mut child = command.spawn()?;
	let pid = libc::pid_t::try_from(child.id()).ok();
	if let (Some(relay), Some(pid)) = (&relay, pid) {
		relay.attach(pid);
		let waited = wait_for_exit(pid);
		CHILD.store(0, Ordering::SeqCst);
		while ACTIVE.load(Ordering::SeqCst) != 0 {
			std::hint::spin_loop();
		}
		ended(pid);
		// A failed wait is reported by the reaping wait below.
		let _ = waited;
	}
	child.wait()
}

/// The exit code a finished command stands for: its own, or `128 + signal`
/// when a signal ended it, as a shell reports it.
pub(super) fn exit_code(status: ExitStatus) -> u8 {
	use std::os::unix::process::ExitStatusExt;
	match (status.code(), status.signal()) {
		(Some(code), _) => code as u8,
		(None, Some(signal)) => 128_u8.saturating_add(signal as u8),
		(None, None) => 1,
	}
}

#[cfg(test)]
mod tests;
