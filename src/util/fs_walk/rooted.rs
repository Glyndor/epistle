//! The walk, confined to a trusted root.
//!
//! Every function takes the directory the data lives under next to the path
//! it was asked to touch. The root is resolved once; the part of the path
//! below it is split into plain names, and each name is resolved against the
//! directory already checked and must still lie inside the resolved root.
//! The filesystem calls are made on the resolved value that came out of that
//! check, not on the path the caller passed in.
//!
//! What is refused, and how it shows:
//!
//! - A `..` component, a path that is not under the root, a name that is not
//!   one plain UTF-8 name, or an entry whose resolved location is outside the
//!   root (a link leading out) fail with [`io::ErrorKind::InvalidInput`].
//! - A link inside the root, a link that points nowhere, a special file, or a
//!   file where a directory is needed is skipped with a warning and fails
//!   with [`io::ErrorKind::NotFound`], as the unrooted walk did. An entry
//!   that leads out of the root is warned about too.
//! - A missing entry, and a missing root, are [`io::ErrorKind::NotFound`] for
//!   [`read_dir`] and [`read`]; [`check_directories`] accepts a missing tail
//!   of plain names, root included, and returns it under the root as given.
//!
//! A name is one plain name when [`contained_child`] accepts it, the check
//! the rest of the code uses for a name under a vetted directory; `a..b` is a
//! name, `..` is not.
//!
//! The root may be spelled raw (relative, or under a symlinked prefix) or in
//! its resolved form, and so may the path: either spelling is stripped. Paths
//! that come back from here, entries included, use the resolved spelling. The
//! root itself may be a link, for instance to another disk: it is chosen by
//! trusted code and is resolved, not refused. Everything below it is walked
//! and links are refused there.
//!
//! # What this guarantees
//!
//! It defends against `..`, links that exist when the check runs, and, for
//! [`read`] and [`read_dir`], against an ancestor swapped for a link between
//! the check and the open: after the open the path is resolved again and must
//! still be the same location inside the root, or the call fails with
//! `InvalidInput`; a listing must also still be the same directory (device and
//! inode). A file's inode is not compared, because writers replace sidecars
//! with a rename and a reader that raced one is not an escape. That closes the
//! window only up to that comparison. It does not make the walk
//! atomic: a component replaced again after the comparison, or a listing taken
//! while a directory is swapped, is outside what plain path calls can rule
//! out. Replacing components needs write access inside the data directory,
//! which only the service account has.

use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};

use super::{Entries, warn_skipped};
use crate::util::path_containment::contained_child;

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

/// The device and inode of an object, where the platform has them.
type Identity = Option<(u64, u64)>;

fn identity(metadata: &Metadata) -> Identity {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		Some((metadata.dev(), metadata.ino()))
	}
	#[cfg(not(unix))]
	{
		let _ = metadata;
		None
	}
}

/// The root resolved once (`None` when it does not exist), and the plain
/// names of `path` below it. A `.` is skipped; `..`, a prefix, a root
/// component or a name that is not UTF-8 fail.
fn split<'a>(root: &Path, path: &'a Path) -> io::Result<(Option<PathBuf>, Vec<&'a str>)> {
	use std::path::Component;
	let resolved = match root.canonicalize() {
		Ok(resolved) => Some(resolved),
		Err(error) if error.kind() == io::ErrorKind::NotFound => None,
		Err(error) => return Err(error),
	};
	let below = match path.strip_prefix(root) {
		Ok(below) => below,
		Err(_) => match &resolved {
			Some(resolved) => path.strip_prefix(resolved).map_err(|_| escapes_root())?,
			None => return Err(escapes_root()),
		},
	};
	let mut names = Vec::new();
	for component in below.components() {
		match component {
			Component::CurDir => {}
			Component::Normal(name) => names.push(name.to_str().ok_or_else(escapes_root)?),
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
	/// Whether the name is a link.
	link: bool,
	/// The entry itself, not what a link would lead to.
	metadata: Metadata,
}

/// `name` below `parent`, which must itself be a checked, resolved directory.
///
/// `None` only when nothing exists at that name. A link that points nowhere
/// exists and is skipped, so a missing target is never taken for a missing
/// entry. The entry is resolved before anything else looks at it, and must
/// lie inside `root`.
fn entry(root: &Path, parent: &Path, name: &str) -> io::Result<Option<Found>> {
	let joined = contained_child(parent, name)?;
	let metadata = match std::fs::symlink_metadata(&joined) {
		Ok(metadata) => metadata,
		Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	let resolved = match joined.canonicalize() {
		Ok(resolved) => resolved,
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			warn_skipped(&joined);
			return Err(skipped_file());
		}
		Err(error) => return Err(error),
	};
	if !resolved.starts_with(root) {
		warn_skipped(&joined);
		return Err(escapes_root());
	}
	let link = metadata.file_type().is_symlink();
	Ok(Some(Found {
		joined,
		resolved,
		link,
		metadata,
	}))
}

/// Walk `names` down from `start`, requiring plain directories. Returns the
/// deepest directory that exists and how many names it consumed.
fn descend(root: &Path, start: &Path, names: &[&str]) -> io::Result<(PathBuf, usize)> {
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

/// The result of walking the existing part of a path.
struct Walk<'a> {
	/// The resolved root; `None` when the root does not exist.
	root: Option<PathBuf>,
	/// The deepest checked directory, or the root as given when it is missing.
	checked: PathBuf,
	/// The plain names below it that do not exist.
	missing: Vec<&'a str>,
}

/// The directory walk for [`check_directories`] and [`read_dir`]: the root
/// itself must be a directory when it exists, and so must every name below
/// it that exists.
fn walk<'a>(root: &Path, path: &'a Path) -> io::Result<Walk<'a>> {
	let (resolved, names) = split(root, path)?;
	let Some(resolved) = resolved else {
		return Ok(Walk {
			root: None,
			checked: root.to_path_buf(),
			missing: names,
		});
	};
	if !resolved.is_dir() {
		warn_skipped(&resolved);
		return Err(skipped_directory());
	}
	let (checked, consumed) = descend(&resolved, &resolved, &names)?;
	Ok(Walk {
		missing: names[consumed..].to_vec(),
		root: Some(resolved),
		checked,
	})
}

/// Resolve `path` again once it has been opened: it must still be the same
/// location inside `root` and, when `expected` is given, the same object.
fn still_there(root: &Path, path: &Path, expected: Option<Identity>) -> io::Result<()> {
	match path.canonicalize() {
		Ok(now) if now == path && now.starts_with(root) => {}
		Ok(_) => return Err(escapes_root()),
		Err(error) => return Err(error),
	}
	match expected {
		Some(expected) if identity(&std::fs::symlink_metadata(path)?) != expected => {
			Err(escapes_root())
		}
		_ => Ok(()),
	}
}

/// Check `path`, which lies under `root`, and return the checked path.
///
/// Every existing directory from the root down must be a plain directory.
/// A missing tail of plain names, a missing root included, is accepted, so a
/// mailbox that has not received anything yet still opens. Callers use the
/// returned path, not the one they passed in.
pub(crate) fn check_directories(root: &Path, path: &Path) -> io::Result<PathBuf> {
	let walked = walk(root, path)?;
	let mut checked = walked.checked;
	checked.extend(walked.missing);
	Ok(checked)
}

/// List the directory `path` under `root`, skipping links and special files.
pub(crate) fn read_dir(root: &Path, path: impl AsRef<Path>) -> io::Result<Entries> {
	let walked = walk(root, path.as_ref())?;
	let (Some(root), true) = (walked.root, walked.missing.is_empty()) else {
		return Err(not_found());
	};
	let expected = identity(&std::fs::symlink_metadata(&walked.checked)?);
	#[cfg(test)]
	hook::run();
	let entries = std::fs::read_dir(&walked.checked)?;
	still_there(&root, &walked.checked, Some(expected))?;
	Ok(Entries(entries))
}

/// Read the regular file `path` under `root`.
///
/// A link or special file at the leaf is refused before it is opened, the
/// open does not follow a link or block on a FIFO, and the opened file is
/// checked again, and the path it was opened by must still resolve to the
/// same place inside the root.
pub(crate) fn read(root: &Path, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
	use std::io::Read;
	let (resolved, names) = split(root, path.as_ref())?;
	let resolved = resolved.ok_or_else(not_found)?;
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
	#[cfg(test)]
	hook::run();
	let mut file = options.open(&found.resolved)?;
	if !file.metadata()?.is_file() {
		warn_skipped(&found.joined);
		return Err(skipped_file());
	}
	// Only the location is compared for a file, not its inode: writers replace
	// sidecars with a rename, and a reader that raced one is not an escape.
	still_there(&resolved, &found.resolved, None)?;
	let mut bytes = Vec::new();
	file.read_to_end(&mut bytes)?;
	Ok(bytes)
}

/// [`read`], as UTF-8 text.
pub(crate) fn read_to_string(root: &Path, path: impl AsRef<Path>) -> io::Result<String> {
	String::from_utf8(read(root, path)?)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// A seam for tests to change the tree between the check and the open.
#[cfg(test)]
pub(super) mod hook {
	use std::cell::RefCell;

	thread_local! {
		static BEFORE_OPEN: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
	}

	pub(in crate::util::fs_walk) fn set(action: impl Fn() + 'static) {
		BEFORE_OPEN.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
	}

	pub(super) fn run() {
		BEFORE_OPEN.with(|slot| {
			if let Some(action) = slot.borrow_mut().take() {
				action();
			}
		});
	}
}
