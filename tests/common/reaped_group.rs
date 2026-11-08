//! A child process a test starts in a group of its own and that never outlives
//! the test.
//!
//! A test that starts a long-running child and then panics, times out or is
//! interrupted leaves that child running, and a shell loop nobody stops stays
//! for hours. [`GroupChild`] kills the whole group of the child, and reaps it,
//! when it is dropped before the child was waited for, on every path out of
//! the test. A test process that is itself killed with SIGKILL runs no `Drop`,
//! so the script the child runs must also end by itself: [`bounded_loop`]
//! builds a loop with a hard ceiling of [`LIFETIME`].
//! Meant for `#[path]` inclusion, so it depends on nothing else in `common`.
#![allow(dead_code)]

use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::time::Duration;

/// The longest a script from [`bounded_loop`] lives, whatever the test does.
pub const LIFETIME: Duration = Duration::from_secs(60);

/// Shell text that idles in steps of 0.1 s for at most [`LIFETIME`] and then
/// ends, so a wait never outlives its test even if the test process is killed.
pub fn bounded_loop() -> String {
	format!(
		"i=0; while [ $i -lt {} ]; do sleep 0.1; i=$((i + 1)); done",
		LIFETIME.as_millis() / 100
	)
}

/// A child started as the leader of its own process group, killed with that
/// group on drop unless it was waited for.
pub struct GroupChild {
	child: Child,
	reaped: bool,
}

impl GroupChild {
	/// Start `command` as the leader of a new process group.
	pub fn spawn(command: &mut Command) -> std::io::Result<Self> {
		let child = command.process_group(0).spawn()?;
		Ok(Self {
			child,
			reaped: false,
		})
	}

	/// The pid of the child, which is also the id of its group.
	pub fn id(&self) -> u32 {
		self.child.id()
	}

	/// Send `signal` to the whole group, never to the calling test.
	pub fn signal_group(&self, signal: libc::c_int) {
		let Ok(pid) = libc::pid_t::try_from(self.child.id()) else {
			return;
		};
		if pid > 1 && !self.reaped {
			// SAFETY: the negative pid names the group this value started
			// and has not reaped yet, so the number cannot belong to another.
			unsafe { libc::kill(-pid, signal) };
		}
	}

	/// Wait for the child to end.
	pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
		let status = self.child.wait()?;
		self.reaped = true;
		Ok(status)
	}
}

impl std::ops::Deref for GroupChild {
	type Target = Child;
	fn deref(&self) -> &Child {
		&self.child
	}
}

impl std::ops::DerefMut for GroupChild {
	fn deref_mut(&mut self) -> &mut Child {
		&mut self.child
	}
}

impl Drop for GroupChild {
	fn drop(&mut self) {
		if !self.reaped {
			self.signal_group(libc::SIGKILL);
			let _ = self.child.wait();
		}
	}
}
