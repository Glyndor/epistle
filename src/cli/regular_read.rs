//! The one way a command reads a file it did not just create.
//!
//! A plain `fs::read` opens the path and waits there when it is a FIFO whose
//! writer never comes, and the commands that read configuration, keys and the
//! generated compose file often do it with the configuration lock in hand. The
//! open here carries `O_NONBLOCK` and the descriptor has to say it is a
//! regular file before a byte is read, so the wait never starts.
//!
//! A link is followed (`compose.yaml` and the secrets are routinely links into
//! another directory of the installation) and the bytes come from the same
//! descriptor that was checked, so a path swapped after the check does not
//! decide what is read. The callers that must refuse a link use their own
//! open (see `init::apply_config_read`).

use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::Path;

/// What the refusal says, so a caller that wraps the error can tell it from
/// the failures of the operating system.
pub(crate) const NOT_REGULAR: &str = "not a regular file";

/// The bytes of the regular file at `path`. A missing file is
/// [`io::ErrorKind::NotFound`] as for `fs::read`; anything that is not a
/// regular file (a FIFO, a device, a directory) is [`io::ErrorKind::InvalidInput`]
/// carrying [`NOT_REGULAR`], and nothing is read from it.
pub(crate) fn read(path: &Path) -> io::Result<Vec<u8>> {
	read_with_metadata(path).map(|(bytes, _)| bytes)
}

/// [`read`] with the metadata of the descriptor the bytes came from, for the
/// callers that compare it with the file at the path later.
pub(crate) fn read_with_metadata(path: &Path) -> io::Result<(Vec<u8>, Metadata)> {
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NONBLOCK);
	}
	let mut file: File = options.open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		return Err(io::Error::new(io::ErrorKind::InvalidInput, NOT_REGULAR));
	}
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)?;
	Ok((bytes, metadata))
}

/// [`read`] as UTF-8 text, for the files that are text.
pub(crate) fn read_to_string(path: &Path) -> io::Result<String> {
	String::from_utf8(read(path)?)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// `true` when `error` is the refusal of a file that is not a regular one.
pub(crate) fn is_not_regular(error: &io::Error) -> bool {
	error.kind() == io::ErrorKind::InvalidInput && error.to_string() == NOT_REGULAR
}

/// A named pipe at `path`, the shape that turns a blocking read into a wait.
#[cfg(all(test, unix))]
pub(crate) fn fifo_at(path: &Path) {
	let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("nul-free");
	// SAFETY: `c_path` is a NUL-terminated string valid for the call.
	let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
	assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
}

/// `run(path)` if it comes back inside five seconds. A fifo with no writer
/// releases a blocking reader only when a writer appears, so the deadline is
/// the assertion; the writer opened afterwards lets the thread finish instead
/// of holding it for the rest of the run.
#[cfg(all(test, unix))]
pub(crate) fn bounded<T: Send + 'static>(
	path: &Path,
	run: impl FnOnce(&Path) -> T + Send + 'static,
) -> T {
	let (sender, receiver) = std::sync::mpsc::channel();
	let target = path.to_path_buf();
	let thread = std::thread::spawn(move || sender.send(run(&target)));
	let value = receiver.recv_timeout(std::time::Duration::from_secs(5));
	if value.is_err() {
		use std::os::unix::fs::OpenOptionsExt;
		// Non-blocking, so a release that finds no reader fails instead of
		// joining the wait it is there to end.
		drop(
			std::fs::OpenOptions::new()
				.write(true)
				.custom_flags(libc::O_NONBLOCK)
				.open(path),
		);
	}
	let result = value.unwrap_or_else(|_| panic!("the reader waited on the path"));
	thread.join().expect("reader thread").expect("hung up");
	result
}

#[cfg(all(test, unix))]
#[path = "regular_read_tests.rs"]
mod tests;
