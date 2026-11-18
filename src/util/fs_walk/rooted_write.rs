//! Writes, locks, renames and removals confined to a trusted root.
//!
//! The counterpart of [`super::rooted`] for the operations that change the
//! tree or open a file by a name that may not exist yet. Every function takes
//! the trusted directory the data lives under (the data directory, never the
//! mailbox directory it was handed) next to the path it was asked to touch.
//!
//! Each function resolves the root, resolves the directory that must already
//! exist (the path itself for a read, its parent for a name that may be new),
//! and refuses it unless the resolved value lies under the resolved root. The
//! filesystem call is made on that resolved value, never on the path the
//! caller passed in. A new final name must be one plain name, as
//! [`contained_child`] requires, and is only ever joined to the checked
//! directory.
//!
//! What is refused: a `..`, a directory that resolves outside the root, a name
//! that is not one plain UTF-8 name, and, for the opens, a link or special
//! file at the final name. Each fails with [`io::ErrorKind::InvalidInput`]. A
//! missing directory is [`io::ErrorKind::NotFound`], as the plain call gave.
//!
//! This closes links that exist when the check runs and the leaf of an open
//! (it is opened without following a link). It does not make the sequence
//! atomic against a component swapped between the check and the call; that
//! needs write access inside the data directory, which only the service
//! account has.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::util::path_containment::contained_child;

fn escapes_root() -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidInput,
		"path is not inside its root directory",
	)
}

fn not_regular() -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidInput,
		"path is not a regular file inside its root directory",
	)
}

/// `path` resolved, which must exist and lie under `root`.
fn existing(root: &Path, path: &Path) -> io::Result<PathBuf> {
	let root = root.canonicalize()?;
	let checked = path.canonicalize()?;
	if !checked.starts_with(&root) {
		return Err(escapes_root());
	}
	Ok(checked)
}

/// The resolved directory that holds `path`, and `path`'s final name joined
/// under it. The directory must exist and lie under `root`; the name may be
/// new.
fn leaf(root: &Path, path: &Path) -> io::Result<(PathBuf, PathBuf)> {
	let name = path
		.file_name()
		.and_then(|name| name.to_str())
		.ok_or_else(escapes_root)?;
	let parent = path.parent().ok_or_else(escapes_root)?;
	let root = root.canonicalize()?;
	let checked = parent.canonicalize()?;
	if !checked.starts_with(&root) {
		return Err(escapes_root());
	}
	let leaf = contained_child(&checked, name)?;
	if !leaf.starts_with(&root) {
		return Err(escapes_root());
	}
	Ok((checked, leaf))
}

/// Open the regular file `path` under `root` with `options`, creating it when
/// the options say so. A link or special file at the leaf is refused.
fn open_regular(root: &Path, path: &Path, options: &mut OpenOptions) -> io::Result<File> {
	let (_, leaf) = leaf(root, path)?;
	match std::fs::symlink_metadata(&leaf) {
		Ok(found) if !found.is_file() => return Err(not_regular()),
		Ok(_) => {}
		Err(error) if error.kind() == io::ErrorKind::NotFound => {}
		Err(error) => return Err(error),
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		// A leaf replaced by a link after the check is not followed, and a
		// FIFO put there does not block the open.
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let file = options.open(&leaf)?;
	if !file.metadata()?.is_file() {
		return Err(not_regular());
	}
	Ok(file)
}

/// Open the regular file `path` under `root` for reading.
pub(crate) fn open_read(root: &Path, path: &Path) -> io::Result<File> {
	open_regular(root, path, OpenOptions::new().read(true))
}

/// Open, creating it when absent and without truncating it, the regular file
/// `path` under `root` that a lock is taken on.
pub(crate) fn open_lock(root: &Path, path: &Path) -> io::Result<File> {
	open_regular(
		root,
		path,
		OpenOptions::new().create(true).truncate(false).write(true),
	)
}

/// Open, creating it when absent, the regular file `path` under `root` for
/// appending.
pub(crate) fn open_append(root: &Path, path: &Path) -> io::Result<File> {
	open_regular(root, path, OpenOptions::new().create(true).append(true))
}

/// Replace the file `path` under `root` with `bytes` in one rename, so a
/// reader sees the old content or the new one and never a partial write.
///
/// The bytes go to a staging file of a unique name next to `path`, created
/// with `create_new`, and the rename stays inside the checked directory. The
/// staging file is removed again when the write or the rename fails.
pub(crate) fn write_atomic(root: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
	let (parent, leaf) = leaf(root, path)?;
	let name = leaf
		.file_name()
		.and_then(|name| name.to_str())
		.ok_or_else(escapes_root)?;
	let staging = contained_child(&parent, &format!("{name}.{}.tmp", Uuid::now_v7()))?;
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&staging)?;
	let written = file.write_all(bytes).and_then(|()| file.flush());
	drop(file);
	let moved = written.and_then(|()| std::fs::rename(&staging, &leaf));
	if moved.is_err() {
		let _ = std::fs::remove_file(&staging);
	}
	moved
}

/// Move `from` to `to`, both under `root`. Each operand is checked on its
/// own: its directory must resolve under the root.
pub(crate) fn rename(root: &Path, from: &Path, to: &Path) -> io::Result<()> {
	let (_, from) = leaf(root, from)?;
	let (_, to) = leaf(root, to)?;
	std::fs::rename(from, to)
}

/// Remove the file `path` under `root`. A link at the leaf is removed itself,
/// not what it points at.
pub(crate) fn remove_file(root: &Path, path: &Path) -> io::Result<()> {
	let (_, leaf) = leaf(root, path)?;
	std::fs::remove_file(leaf)
}

/// The metadata of `path`, which must exist under `root`.
pub(crate) fn metadata(root: &Path, path: &Path) -> io::Result<Metadata> {
	let checked = existing(root, path)?;
	std::fs::metadata(checked)
}

/// Create the directory `path` and the missing ones above it, all under
/// `root`. Each name that is created is one plain name joined to a directory
/// that was resolved and checked, and the created directory is resolved and
/// checked again before the next name is added.
pub(crate) fn create_dir_all(root: &Path, path: &Path) -> io::Result<()> {
	let root = root.canonicalize()?;
	let mut missing = Vec::new();
	let mut current = path;
	let mut checked = loop {
		match current.canonicalize() {
			Ok(resolved) => break resolved,
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				missing.push(current.file_name().ok_or_else(escapes_root)?);
				current = current.parent().ok_or_else(escapes_root)?;
			}
			Err(error) => return Err(error),
		}
	};
	if !checked.starts_with(&root) {
		return Err(escapes_root());
	}
	for name in missing.into_iter().rev() {
		let name = name.to_str().ok_or_else(escapes_root)?;
		let next = contained_child(&checked, name)?;
		match std::fs::create_dir(&next) {
			Ok(()) => {}
			// Another writer made it first; a link there is not a directory.
			Err(error)
				if error.kind() == io::ErrorKind::AlreadyExists
					&& std::fs::symlink_metadata(&next).is_ok_and(|found| found.is_dir()) => {}
			Err(error) => return Err(error),
		}
		let resolved = next.canonicalize()?;
		if !resolved.starts_with(&root) {
			return Err(escapes_root());
		}
		checked = resolved;
	}
	Ok(())
}
