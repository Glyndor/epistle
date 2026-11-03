//! Reading a file a process keeps for itself and then acts on, such as the
//! TLSA state or the dns-01 journal: only the regular file at that very
//! name, and only while it has no other name.

use std::io::{self, Read};
use std::path::Path;

/// The bytes of the file at `path`, `None` when nothing is there.
///
/// Refused with an error when the entry is a symlink (the open does not
/// follow it), is not a regular file, or has a second name (a hard link).
/// Either way the content could be rewritten through another name by
/// whoever left the entry: with a split stack, the mail container, which
/// could write these directories before the split and writes the rest of
/// data_dir after it. The owner is not checked: `mail` and `certs` run as
/// the same user, so the owner tells them apart no better than it tells
/// either from the operator.
pub(crate) fn read_unshared(path: &Path) -> io::Result<Option<Vec<u8>>> {
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let mut file = match options.open(path) {
		Ok(file) => file,
		Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	// `fstat` on the descriptor: what was opened is what is checked.
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		return Err(io::Error::other("not a regular file"));
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if metadata.nlink() != 1 {
			return Err(io::Error::other(format!(
				"the file has {} names (a hard link); only a file with one name is read",
				metadata.nlink()
			)));
		}
	}
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)?;
	Ok(Some(bytes))
}
