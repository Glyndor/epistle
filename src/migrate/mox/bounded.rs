//! Time and size bounds for regular migration input files.

use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const READ_TIMEOUT: Duration = Duration::from_secs(30);
static READING: AtomicBool = AtomicBool::new(false);

struct Slot;
impl Drop for Slot {
	fn drop(&mut self) {
		READING.store(false, Ordering::Release);
	}
}

fn timed_out() -> io::Error {
	io::Error::new(io::ErrorKind::TimedOut, "migration file read timed out")
}

fn within<T: Send + 'static>(
	timeout: Duration,
	operation: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
	let deadline = Instant::now() + timeout;
	// Keep at most one outstanding filesystem read, even if a filesystem stalls.
	while READING
		.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
		.is_err()
	{
		if Instant::now() >= deadline {
			return Err(timed_out());
		}
		std::thread::sleep(Duration::from_millis(1));
	}
	let slot = Slot;
	let (send, receive) = std::sync::mpsc::sync_channel(1);
	std::thread::Builder::new()
		.name("migration-file-read".into())
		.spawn(move || {
			let _slot = slot;
			let _ = send.send(operation());
		})?;
	receive
		.recv_timeout(deadline.saturating_duration_since(Instant::now()))
		.map_err(|_| timed_out())?
}

/// Read regular UTF-8 input within 30 seconds and `limit` bytes.
pub(super) fn read(path: &Path, limit: usize) -> io::Result<String> {
	let path = path.to_path_buf();
	within(READ_TIMEOUT, move || {
		let mut options = std::fs::OpenOptions::new();
		options.read(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.custom_flags(libc::O_NONBLOCK);
		}
		let handle = options.open(path)?;
		if !handle.metadata()?.is_file() {
			return Err(io::Error::other("migration input must be a regular file"));
		}
		let mut text = String::new();
		handle.take(limit as u64 + 1).read_to_string(&mut text)?;
		if text.len() > limit {
			return Err(io::Error::other(format!("larger than {limit} bytes")));
		}
		Ok(text)
	})
}

#[cfg(test)]
#[path = "bounded_tests.rs"]
mod tests;
