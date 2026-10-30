//! The generated compose file's own lock, taken with a deadline.
//!
//! `stack update` and `stack resources set` rewrite that file under a lock
//! beside it, and they hold the common lock while they do. The holder of this
//! second lock can be an older `epistle` command or a local tool that only
//! respects this one, and a plain `flock` waits for as long as the other
//! process keeps it, so the wait has to end somewhere: the command announces
//! it once, gives up when the budget the common lock started is spent, says
//! which file it was waiting for and drops the common lock with it. Nothing is
//! recorded in this lock, so the wait names the file and not its holder.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::storage::lock::FileLock;

/// Take the lock that guards a rewrite of the generated compose file. The
/// command already holds the common lock, so the wait is what is left of the
/// budget that lock spent from, not a second full one.
pub(in crate::cli) fn acquire(path: &Path) -> Result<FileLock, String> {
	acquire_within(path, crate::cli::service::lock::remaining())
}

/// [`acquire`] with the deadline passed in, so a test does not have to wait
/// the full half minute to see the refusal.
pub(in crate::cli) fn acquire_within(path: &Path, within: Duration) -> Result<FileLock, String> {
	match FileLock::try_acquire(path) {
		Ok(Some(held)) => Ok(held),
		Ok(None) => wait_for(path, within),
		Err(error) => Err(format!("cannot lock {}: {error}", path.display())),
	}
}

/// Wait for the holder to finish and give up at the deadline. Each attempt
/// opens the lock again, so the descriptor the lock is taken on is the one
/// `FileLock` hands out, and it is dropped again on every attempt that finds
/// the lock held elsewhere.
fn wait_for(path: &Path, within: Duration) -> Result<FileLock, String> {
	let deadline = Instant::now() + within;
	let mut announced = false;
	loop {
		match FileLock::try_acquire(path) {
			Ok(Some(held)) => return Ok(held),
			Ok(None) => {}
			Err(error) => return Err(format!("cannot lock {}: {error}", path.display())),
		}
		if !announced {
			announced = true;
			crate::cli::style::warn(format!(
				"{} is held by another process; waiting up to {}s for it to finish",
				path.display(),
				within.as_secs()
			));
		}
		if Instant::now() >= deadline {
			return Err(format!(
				"another process has held {} for longer than {}s; retry once it has finished",
				path.display(),
				within.as_secs()
			));
		}
		std::thread::sleep(crate::cli::service::lock::POLL);
	}
}

#[cfg(test)]
mod tests;
