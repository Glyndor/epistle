//! What is at the path of a secret file before anything is written there.

use std::path::Path;

use super::super::super::apply::ApplyError;

/// The state of a secret file.
pub(super) enum Held {
	/// Nothing is at the path.
	Missing,
	/// A regular, non-empty file, with its bytes.
	Present(Vec<u8>),
}

/// Look at `path` the way the database password is looked at: only a path
/// that does not exist is free to be written. A link, a directory, a FIFO, an
/// empty file or one that cannot be read is an error that names the path, and
/// nothing is replaced, because the operator may have put it there on purpose.
pub(super) fn read(path: &Path) -> Result<Held, ApplyError> {
	let refuse = |why: &str| {
		ApplyError::ExistingSecretUnreadable(
			path.to_path_buf(),
			std::io::Error::other(why.to_string()),
		)
	};
	let metadata = match std::fs::symlink_metadata(path) {
		Ok(metadata) => metadata,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Held::Missing),
		Err(error) => {
			return Err(ApplyError::ExistingSecretUnreadable(
				path.to_path_buf(),
				error,
			));
		}
	};
	if metadata.file_type().is_symlink() {
		return Err(refuse(
			"path is a symlink; remove it (or replace it with the file it pointed at) and rerun",
		));
	}
	if !metadata.file_type().is_file() {
		return Err(refuse("path is not a regular file; remove it and rerun"));
	}
	match crate::cli::regular::read::read(path) {
		Ok(bytes) if !bytes.is_empty() => Ok(Held::Present(bytes)),
		Ok(_) => Err(refuse("file is empty; remove it and rerun")),
		Err(error) => Err(ApplyError::ExistingSecretUnreadable(
			path.to_path_buf(),
			error,
		)),
	}
}

/// `bytes` without the line ending an editor may have added.
pub(super) fn trimmed(bytes: &[u8]) -> &[u8] {
	let mut end = bytes.len();
	while end > 0 && matches!(bytes[end - 1], b'\n' | b'\r') {
		end -= 1;
	}
	&bytes[..end]
}
