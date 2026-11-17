//! The walk, confined to a trusted root.
//!
//! Every function takes the directory the data lives under next to the path
//! it was asked to touch. The root is resolved once; the part of the path
//! below it is split into plain names, and each name is resolved against the
//! directory already checked and must still lie inside the resolved root.
//! The filesystem calls see only the value that came out of that check, never
//! the path the caller passed in.
//!
//! What is refused, and how it shows:
//!
//! - A `..` component, a path that is not under the root, or an entry whose
//!   resolved location is outside the root (a link leading out) fail with
//!   [`io::ErrorKind::InvalidInput`].
//! - A link inside the root, a special file, or a file where a directory is
//!   needed is skipped with a warning and fails with
//!   [`io::ErrorKind::NotFound`], as the unrooted walk did.
//! - A missing entry is [`io::ErrorKind::NotFound`] for [`read_dir`] and
//!   [`read`]; [`check_directories`] accepts a missing tail of plain names.
//!
//! The root may be spelled raw (relative, or under a symlinked prefix) or in
//! its resolved form, and so may the path: either spelling is stripped. Paths
//! that come back from here, entries included, use the resolved spelling.

use std::ffi::OsStr;
use std::fs::Metadata;
use std::io;
use std::path::{Component, Path, PathBuf};

use super::{Entries, warn_skipped};

fn escapes_root() -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidInput,
		"path is not inside its root directory",
	)
}

fn skipped_directory() -> io::Error {
	io::Error::new(io::ErrorKind::NotFound, "skipped non-directory data path")
}

fn skipped_file() -> io::Error {
	io::Error::new(io::ErrorKind::NotFound, "skipped non-regular data file")
}

fn not_found() -> io::Error {
	io::Error::from(io::ErrorKind::NotFound)
}

/// The root resolved once, and the plain names of `path` below it.
///
/// A `.` is skipped; `..`, a prefix or a root component fail. Every other
/// component is one name, so a name such as `a..b` is accepted.
fn split<'a>(root: &Path, path: &'a Path) -> io::Result<(PathBuf, Vec<&'a OsStr>)> {
	let resolved = root.canonicalize()?;
	let below = path
		.strip_prefix(root)
		.or_else(|_| path.strip_prefix(&resolved))
		.map_err(|_| escapes_root())?;
	let mut names = Vec::new();
	for component in below.components() {
		match component {
			Component::CurDir => {}
			Component::Normal(name) => names.push(name),
			_ => return Err(escapes_root()),
		}
	}
	Ok((resolved, names))
}

/// One resolved entry below a checked directory.
struct Found {
	/// The name as joined under the checked directory.
	joined: PathBuf,
	/// Its resolved location, inside the root.
	resolved: PathBuf,
	/// Whether the name is a link: it resolves somewhere other than itself.
	link: bool,
	metadata: Metadata,
}

/// `name` below `parent`, which must itself be a checked, resolved directory.
///
/// `None` when nothing exists at that name. The entry is resolved before
/// anything else looks at it, and must lie inside `root`.
fn entry(root: &Path, parent: &Path, name: &OsStr) -> io::Result<Option<Found>> {
	let joined = parent.join(name);
	let resolved = match joined.canonicalize() {
		Ok(resolved) => resolved,
		Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	if !resolved.starts_with(root) {
		return Err(escapes_root());
	}
	let link = resolved != joined;
	let metadata = std::fs::symlink_metadata(&resolved)?;
	Ok(Some(Found {
		joined,
		resolved,
		link,
		metadata,
	}))
}

/// Walk `names` down from `start`, requiring plain directories. Returns the
/// deepest directory that exists and how many names it consumed.
fn descend(root: &Path, start: &Path, names: &[&OsStr]) -> io::Result<(PathBuf, usize)> {
	let mut current = start.to_path_buf();
	for (index, name) in names.iter().enumerate() {
		let Some(found) = entry(root, &current, name)? else {
			return Ok((current, index));
		};
		if found.link || !found.metadata.is_dir() {
			warn_skipped(&found.joined);
			return Err(skipped_directory());
		}
		current = found.resolved;
	}
	Ok((current, names.len()))
}

/// The directory walk for [`check_directories`] and [`read_dir`]: the root
/// itself must be a directory, and so must every name below it that exists.
fn walk(root: &Path, path: &Path) -> io::Result<(PathBuf, usize, Vec<PathBuf>)> {
	let (resolved, names) = split(root, path)?;
	if !resolved.is_dir() {
		warn_skipped(&resolved);
		return Err(skipped_directory());
	}
	let (checked, consumed) = descend(&resolved, &resolved, &names)?;
	let missing = names[consumed..].iter().map(PathBuf::from).collect();
	Ok((checked, consumed, missing))
}

/// Check `path`, which lies under `root`, and return the checked path.
///
/// Every existing directory from the root down must be a plain directory.
/// A missing tail of plain names is accepted, so a mailbox that has not
/// received anything yet still opens. Callers use the returned path, not the
/// one they passed in.
pub(crate) fn check_directories(root: &Path, path: &Path) -> io::Result<PathBuf> {
	let (mut checked, _, missing) = walk(root, path)?;
	checked.extend(missing);
	Ok(checked)
}

/// List the directory `path` under `root`, skipping links and special files.
pub(crate) fn read_dir(root: &Path, path: impl AsRef<Path>) -> io::Result<Entries> {
	let (checked, _, missing) = walk(root, path.as_ref())?;
	if !missing.is_empty() {
		return Err(not_found());
	}
	Ok(Entries(std::fs::read_dir(checked)?))
}

/// Read the regular file `path` under `root`.
///
/// A link or special file at the leaf is refused before it is opened, the
/// open does not follow a link or block on a FIFO, and the opened file is
/// checked again.
pub(crate) fn read(root: &Path, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
	use std::io::Read;
	let (resolved, names) = split(root, path.as_ref())?;
	let (leaf, parents) = names.split_last().ok_or_else(escapes_root)?;
	let (dir, consumed) = descend(&resolved, &resolved, parents)?;
	if consumed < parents.len() {
		return Err(not_found());
	}
	let found = entry(&resolved, &dir, leaf)?.ok_or_else(not_found)?;
	if found.link || !found.metadata.is_file() {
		warn_skipped(&found.joined);
		return Err(skipped_file());
	}
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		// A replaced leaf must not follow a link or block on a FIFO after the check.
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let mut file = options.open(&found.resolved)?;
	if !file.metadata()?.is_file() {
		warn_skipped(&found.joined);
		return Err(skipped_file());
	}
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)?;
	Ok(bytes)
}

/// [`read`], as UTF-8 text.
pub(crate) fn read_to_string(root: &Path, path: impl AsRef<Path>) -> io::Result<String> {
	String::from_utf8(read(root, path)?)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
