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

use std::path::Path;

use crate::cli::regular_read;

/// The bytes of the generated compose file, or `None` when the install has
/// none. The reason a read failed, naming the path it could not read.
pub(crate) fn read(path: &Path) -> Result<Option<Vec<u8>>, String> {
	match regular_read::read(path) {
		Ok(bytes) => Ok(Some(bytes)),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
		Err(error) if regular_read::is_not_regular(&error) => {
			Err(format!("{} must be a regular file", path.display()))
		}
		Err(error) => Err(format!("cannot read {}: {error}", path.display())),
	}
}

/// A named pipe at `path`, shared by the tests of every reader.
#[cfg(all(test, unix))]
pub(crate) use crate::cli::regular_read::fifo_at;

#[cfg(all(test, unix))]
#[path = "compose_read_tests.rs"]
mod tests;
