//! File copies for staging that never follow a symbolic link and never open
//! a special file.
//!
//! The staging directory sits in the service account's home, which the
//! account can rename entries in, so every step below the directory goes
//! through an open descriptor (`/proc/self/fd/N/name`), never a path the
//! account could swap for a link between a check and a use. A file is
//! classified by `lstat` before it is opened, opened with `O_NOFOLLOW` and
//! `O_NONBLOCK` (a fifo cannot block the open), and checked again with
//! `fstat` on the descriptor.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

/// Hands a staged file or directory to the service account. The path is
/// the entry's place inside the staging directory, for tests to assert on.
pub(crate) type Chown<'a> = &'a dyn Fn(&File, &Path) -> io::Result<()>;

/// What is left of a size bound while a copy runs.
pub(crate) struct Budget {
	pub(crate) left: u64,
	pub(crate) limit: u64,
	/// The path the operator named, for the error when the bound is hit.
	pub(crate) shown: PathBuf,
}

impl Budget {
	pub(crate) fn new(limit: u64, shown: &Path) -> Self {
		Self {
			left: limit,
			limit,
			shown: shown.to_path_buf(),
		}
	}

	fn exceeded(&self) -> io::Error {
		io::Error::other(format!(
			"{} is larger than the {} copied for the service account",
			self.shown.display(),
			size(self.limit)
		))
	}
}

fn size(bytes: u64) -> String {
	const MIB: u64 = 1024 * 1024;
	if bytes >= 1024 * MIB && bytes.is_multiple_of(1024 * MIB) {
		format!("{} GiB", bytes / (1024 * MIB))
	} else if bytes >= MIB && bytes.is_multiple_of(MIB) {
		format!("{} MiB", bytes / MIB)
	} else {
		format!("{bytes} bytes")
	}
}

/// `name` inside the directory open as `dir`, reached through the
/// descriptor so a rename of the directory cannot redirect it.
pub(crate) fn under(dir: &File, name: impl AsRef<Path>) -> PathBuf {
	PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name)
}

/// Open a directory, refusing a symbolic link in its last component.
pub(crate) fn open_dir(path: &Path) -> io::Result<File> {
	OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
		.open(path)
}

fn open_file(path: &Path) -> io::Result<File> {
	OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
		.open(path)
}

/// Create the directory `name` in `dir`, mode 0700, and open it.
pub(crate) fn make_dir(dir: &File, name: impl AsRef<Path>) -> io::Result<File> {
	let path = under(dir, name);
	DirBuilder::new().mode(0o700).create(&path)?;
	let opened = open_dir(&path)?;
	opened.set_permissions(Permissions::from_mode(0o700))?;
	Ok(opened)
}

/// What a named path is, by `lstat`: the copies take only these two.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Node {
	File,
	Dir,
}

/// Classify `path` without following it. A symbolic link or a special
/// file (fifo, socket, device) is refused with `shown` in the message.
pub(crate) fn classify(path: &Path, shown: &Path) -> io::Result<(Node, fs::Metadata)> {
	let meta = fs::symlink_metadata(path).map_err(|error| {
		io::Error::new(
			error.kind(),
			format!("reading {}: {error}", shown.display()),
		)
	})?;
	let kind = meta.file_type();
	if kind.is_symlink() {
		return Err(io::Error::other(format!(
			"{} is a symbolic link; it is not followed, name the file it points to",
			shown.display()
		)));
	}
	if kind.is_dir() {
		Ok((Node::Dir, meta))
	} else if kind.is_file() {
		Ok((Node::File, meta))
	} else {
		Err(special(shown))
	}
}

fn special(shown: &Path) -> io::Error {
	io::Error::other(format!(
		"{} is not a regular file or a directory; it is not copied",
		shown.display()
	))
}

/// Copy the regular file at `source` into `dir` as `name`, mode 0600,
/// charging `budget`, then hand it over with `chown`.
pub(crate) fn copy_file(
	source: &Path,
	shown: &Path,
	dir: &File,
	name: &Path,
	rel: &Path,
	budget: &mut Budget,
	chown: Chown,
) -> io::Result<()> {
	let file = open_file(source).map_err(|error| {
		io::Error::new(
			error.kind(),
			format!("reading {}: {error}", shown.display()),
		)
	})?;
	let meta = file.metadata()?;
	if !meta.is_file() {
		return Err(special(shown));
	}
	if meta.len() > budget.left {
		return Err(budget.exceeded());
	}
	let target = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW)
		.open(under(dir, name))?;
	target.set_permissions(Permissions::from_mode(0o600))?;
	let copied = io::copy(
		&mut (&file).take(budget.left.saturating_add(1)),
		&mut &target,
	)?;
	if copied > budget.left {
		return Err(budget.exceeded());
	}
	budget.left -= copied;
	chown(&target, rel)
}

/// Copy everything in the directory open as `source` into the one open as
/// `target`: directories 0700, files 0600, each handed over with `chown`.
/// A symbolic link or a special file anywhere in the tree stops the copy.
pub(crate) fn copy_tree(
	source: &File,
	target: &File,
	shown: &Path,
	rel: &Path,
	budget: &mut Budget,
	chown: Chown,
) -> io::Result<()> {
	let entries = fs::read_dir(under(source, "")).map_err(|error| {
		io::Error::new(
			error.kind(),
			format!("reading {}: {error}", shown.display()),
		)
	})?;
	for entry in entries {
		let entry = entry?;
		let name = PathBuf::from(entry.file_name());
		let (shown, rel) = (shown.join(&name), rel.join(&name));
		let kind = entry.file_type()?;
		if kind.is_symlink() {
			return Err(io::Error::other(format!(
				"{} is a symbolic link; links inside a copied directory are not followed",
				shown.display()
			)));
		} else if kind.is_dir() {
			let from = open_dir(&under(source, &name))?;
			let to = make_dir(target, &name)?;
			chown(&to, &rel)?;
			copy_tree(&from, &to, &shown, &rel, budget, chown)?;
		} else if kind.is_file() {
			copy_file(
				&under(source, &name),
				&shown,
				target,
				&name,
				&rel,
				budget,
				chown,
			)?;
		} else {
			return Err(special(&shown));
		}
	}
	Ok(())
}

/// Open `rel` below the directory open as `dir`, one component at a time
/// and never through a symbolic link.
pub(crate) fn open_beneath(dir: &File, rel: &Path, want_dir: bool) -> io::Result<File> {
	let parts: Vec<_> = rel
		.components()
		.filter_map(|part| match part {
			Component::Normal(name) => Some(name),
			_ => None,
		})
		.collect();
	let Some((last, walk)) = parts.split_last() else {
		return Err(io::Error::from(io::ErrorKind::InvalidInput));
	};
	let mut current = dir.try_clone()?;
	for part in walk {
		current = open_dir(&under(&current, part))?;
	}
	let path = under(&current, last);
	if want_dir {
		return open_dir(&path);
	}
	let file = open_file(&path)?;
	if !file.metadata()?.is_file() {
		return Err(special(rel));
	}
	Ok(file)
}

/// Remove everything inside the directory open as `dir`. Links are
/// removed, never followed.
pub(crate) fn clear(dir: &File) -> io::Result<()> {
	for entry in fs::read_dir(under(dir, ""))? {
		let entry = entry?;
		let path = under(dir, entry.file_name());
		if entry.file_type()?.is_dir() {
			fs::remove_dir_all(path)?;
		} else {
			fs::remove_file(path)?;
		}
	}
	Ok(())
}

#[cfg(test)]
#[path = "copy_tests.rs"]
mod tests;
