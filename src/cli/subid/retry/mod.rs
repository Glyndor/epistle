//! Waiting out the moments when the host is not ready yet.
//!
//! `usermod` takes a lock on `/etc/subuid` and `/etc/subgid` that another
//! tool (`useradd`, `adduser`, a second package script) can hold for a short
//! while, and the account's user manager answers on its bus only a moment
//! after `systemctl start user@<uid>.service` returns. Both failures go away
//! when asked again, so a step that hits one is retried a bounded number of
//! times before the move gives up and undoes itself.

use std::time::Duration;

/// Times a step that can meet a lock is run before its error is reported.
pub(super) const ATTEMPTS: u32 = 5;
/// Pause between two attempts.
pub(super) const WAIT: Duration = Duration::from_secs(2);
/// Times the user manager is asked before it is declared not ready.
pub(super) const MANAGER_ATTEMPTS: u32 = 10;

/// Why an attempt failed, and whether asking again can help.
pub(super) struct Failed {
	/// What to report when no attempt is left.
	pub(super) message: String,
	/// Whether the cause can pass by itself.
	pub(super) transient: bool,
}

/// Whether `usermod` reported that another process holds the lock on a table.
pub(super) fn is_lock_contention(stderr: &str) -> bool {
	let lower = stderr.to_ascii_lowercase();
	["cannot lock", "unable to lock", "try again later"]
		.iter()
		.any(|needle| lower.contains(needle))
}

/// Run `attempt` up to `attempts` times, `wait` apart, while it fails with a
/// transient cause. A permanent failure and the last transient one are
/// returned as they are.
pub(super) fn run(
	attempts: u32,
	wait: Duration,
	mut attempt: impl FnMut() -> Result<(), Failed>,
) -> Result<(), String> {
	let mut tried = 0;
	loop {
		tried += 1;
		match attempt() {
			Ok(()) => return Ok(()),
			Err(failed) if failed.transient && tried < attempts => std::thread::sleep(wait),
			Err(failed) => return Err(failed.message),
		}
	}
}

#[cfg(test)]
mod tests;
