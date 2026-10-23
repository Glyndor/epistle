//! The one way every writer of the generated compose file reads it back.
//!
//! The writers read the file before they take the lock, and one of them reads
//! it under it, so a read that waits makes a command wait with it. A FIFO at
//! the path, or a link to one, waits for a writer that may never come, and it
//! does so while holding the configuration lock. The open therefore carries
//! `O_NONBLOCK`, and the file is refused unless the descriptor says it is a
//! regular one, so the wait never starts.
//!
//! `compose.yaml` is routinely a symlink into another directory of the
//! installation, so the link is followed here: the file behind it is what the
//! reader checks, and the bytes come from that same descriptor, so a path
//! swapped after the check does not decide what is read.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The bytes of the generated compose file, or `None` when the install has
/// none. The reason a read failed, naming the path it could not read.
pub(super) fn read(path: &Path) -> Result<Option<Vec<u8>>, String> {
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NONBLOCK);
	}
	let mut file: File = match options.open(path) {
		Ok(file) => file,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(format!("cannot open {}: {error}", path.display())),
	};
	let metadata = file
		.metadata()
		.map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
	if !metadata.is_file() {
		return Err(format!("{} must be a regular file", path.display()));
	}
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)
		.map_err(|error| format!("cannot read {}: {error}", path.display()))?;
	Ok(Some(bytes))
}

#[cfg(all(test, unix))]
#[path = "compose_read_tests.rs"]
mod tests;
