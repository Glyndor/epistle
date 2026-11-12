//! Reading the configuration file as a bounded, regular file.

use std::io::Read;
use std::path::Path;

use super::ConfigError;

/// The most a configuration file may hold. Real files are a few kilobytes;
/// the cap keeps a file somebody swapped for a huge one, or an endless
/// source, from filling the memory of the process that reads it.
pub(super) const MAX_BYTES: usize = 4 * 1024 * 1024;

/// The text of the configuration file at `path`.
///
/// Anything but a regular file is refused without being read: opening a
/// FIFO would wait for a writer for ever, and a device never ends. The file
/// is opened without blocking and checked through the descriptor it was
/// opened as, so the check and the read are about the same file.
pub(super) fn text(path: &Path) -> Result<String, ConfigError> {
	let read = |source: std::io::Error| ConfigError::Read {
		path: path.to_path_buf(),
		source,
		kind: "config file",
	};
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NONBLOCK);
	}
	let file = options.open(path).map_err(read)?;
	if !file.metadata().map_err(read)?.is_file() {
		return Err(read(std::io::Error::other(
			"the configuration must be a regular file",
		)));
	}
	let mut text = String::new();
	file.take(MAX_BYTES as u64 + 1)
		.read_to_string(&mut text)
		.map_err(read)?;
	if text.len() > MAX_BYTES {
		return Err(read(std::io::Error::other(format!(
			"larger than {MAX_BYTES} bytes"
		))));
	}
	Ok(text)
}
