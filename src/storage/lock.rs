//! Cross-process advisory lock on a sibling file.
//!
//! Every mutation of `accounts.toml`, `app_passwords.toml`, `masked.json`
//! and `api_keys.toml` takes an exclusive [`flock`] on a sibling lock
//! file so the in-flight CLI never races the running server. The CLI
//! and the server are separate processes opening the same path; the
//! kernel blocks (or fails) the second opener so each one reads the
//! fresh on-disk state, applies its change, writes atomically, and only
//! then releases.
//!
//! [`flock`]: https://man7.org/linux/man-pages/man2/flock.2.html

use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

/// Take an exclusive [`flock`] on `fd`, blocking until the kernel grants
/// it. The lock is released when the `File` is closed (which is what
/// `flock(2)` actually does; `LOCK_UN` is best-effort and not required
/// for correctness here).
///
/// [`flock`]: https://man7.org/linux/man-pages/man2/flock.2.html
pub(crate) fn flock_exclusive_blocking(fd: RawFd) -> std::io::Result<()> {
	loop {
		let result = unsafe { libc::flock(fd, libc::LOCK_EX) };
		if result == 0 {
			return Ok(());
		}
		let error = std::io::Error::last_os_error();
		// A signal delivered while waiting interrupts the call; the lock
		// is still wanted, so wait again.
		if error.kind() != std::io::ErrorKind::Interrupted {
			return Err(error);
		}
	}
}

/// Try to take an exclusive [`flock`] on `fd` without blocking. Returns
/// `Err` carrying `EWOULDBLOCK` when another holder keeps it; any
/// other error is a real failure.
///
/// [`flock`]: https://man7.org/linux/man-pages/man2/flock.2.html
#[allow(dead_code)]
pub(crate) fn flock_exclusive_nonblocking(fd: RawFd) -> std::io::Result<()> {
	let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
	if result == 0 {
		Ok(())
	} else {
		Err(std::io::Error::last_os_error())
	}
}

/// Open (creating if absent) the lock file at `path`. The file is
/// closed when the last `File` that wraps it drops; the kernel releases
/// the flock at that point.
pub(crate) fn open_lock_file(path: &Path) -> std::io::Result<File> {
	OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.read(true)
		.open(path)
}

/// An exclusive advisory lock on a sibling file. The lock is released
/// when the guard drops (closing the `File` lets the kernel release the
/// `flock(2)` lock — `LOCK_UN` is fire-and-forget and not required).
pub struct FileLock {
	file: File,
}

impl FileLock {
	/// Acquire an exclusive lock on `path`, creating the file if absent.
	/// Blocks until the kernel grants the lock.
	pub fn acquire(path: &Path) -> std::io::Result<Self> {
		let file = open_lock_file(path)?;
		flock_exclusive_blocking(file.as_raw_fd())?;
		Ok(FileLock { file })
	}

	/// Try to acquire an exclusive lock on `path` without blocking.
	/// Returns `Ok(None)` when another holder keeps the lock; the
	/// `Ok(Some(_))` arm means the caller now holds an exclusive lock.
	#[allow(dead_code)]
	pub fn try_acquire(path: &Path) -> std::io::Result<Option<Self>> {
		let file = open_lock_file(path)?;
		match flock_exclusive_nonblocking(file.as_raw_fd()) {
			Ok(()) => Ok(Some(FileLock { file })),
			Err(error) if error.raw_os_error() == Some(libc::EWOULDBLOCK) => Ok(None),
			Err(error) => Err(error),
		}
	}
}

impl Drop for FileLock {
	fn drop(&mut self) {
		// `flock(2)` releases on close anyway, so the explicit `LOCK_UN`
		// is best-effort cleanup. Swallow the error: a release that
		// races a kernel teardown has no caller to surface it to, and
		// re-trying would not yield a different answer.
		let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
	}
}
