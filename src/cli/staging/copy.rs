//! File copies for staging that never follow a symbolic link, never open a
//! special file, and never decide on a path and then act on it again.
//!
//! The staging directory sits in the service account's home, and the
//! account writes the outputs, so anything below it may change between two
//! looks. Every entry is therefore opened once, relative to a directory
//! already open here (`/proc/self/fd/N/name`), with `O_PATH | O_NOFOLLOW`:
//! that open has no side effect even on a device, and a link is opened as
//! the link. Every decision (type, owner, link count, size) comes from
//! `fstat` on that descriptor, and the data is read through the same inode,
//! reopened by its descriptor rather than by its name.

use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

/// Hands a staged file or directory to the service account. The path is
/// the entry's place inside the staging directory, for tests to assert on.
pub(crate) type Chown<'a> = &'a dyn Fn(&File, &Path) -> io::Result<()>;

/// Who could have written what a copy reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
	/// The operator's own files, named on the command line.
	Operator,
	/// The staging directory after the account's run: every entry must be
	/// the account's (uid), and a file must have a single link, so the
	/// account cannot hand root a hard link to a file it may not read.
	Account(u32),
}

/// What a copy may take: the size left, and whose entries it accepts.
pub(crate) struct Budget {
	pub(crate) left: u64,
	limit: u64,
	/// The path the operator named, for the error when the bound is hit.
	shown: PathBuf,
	free_space: bool,
	pub(crate) source: Source,
}

impl Budget {
	/// A copy into the staging directory, bounded at `limit` bytes.
	pub(crate) fn new(limit: u64, shown: &Path) -> Self {
		Self {
			left: limit,
			limit,
			shown: shown.to_path_buf(),
			free_space: false,
			source: Source::Operator,
		}
	}

	/// A copy bounded by the `room` its target filesystem has to spare.
	pub(crate) fn free_space(room: u64, shown: &Path) -> Self {
		Self {
			free_space: true,
			..Self::new(room, shown)
		}
	}

	/// Accept only entries the account at `uid` owns, with one link.
	pub(crate) fn written_by_account(self, uid: u32) -> Self {
		Self {
			source: Source::Account(uid),
			..self
		}
	}

	fn exceeded(&self) -> io::Error {
		let shown = self.shown.display();
		if self.free_space {
			return io::Error::other(format!(
				"{shown} would leave its filesystem with less than 5% free; nothing was kept"
			));
		}
		io::Error::other(format!(
			"{shown} is larger than the {} copied for the service account",
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

/// `name` inside the directory open as `dir`: the directory is the one this
/// process opened, whatever its name is now. Only `name` is looked up, and
/// every open of it below uses `O_NOFOLLOW`.
pub(crate) fn under(dir: &File, name: impl AsRef<Path>) -> PathBuf {
	fd_path(dir).join(name)
}

fn fd_path(file: &File) -> PathBuf {
	PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn context(shown: &Path) -> impl Fn(io::Error) -> io::Error + '_ {
	move |error| {
		io::Error::new(
			error.kind(),
			format!("reading {}: {error}", shown.display()),
		)
	}
}

/// An entry opened without following it and without reading it, and what
/// `fstat` on that descriptor says it is.
pub(crate) struct Node {
	handle: File,
	pub(crate) meta: Metadata,
}

/// Open `at` as a [`Node`]: `O_PATH | O_NOFOLLOW`, so a link is the link
/// and a device is never opened for reading.
pub(crate) fn open_node(at: &Path, shown: &Path) -> io::Result<Node> {
	let handle = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
		.open(at)
		.map_err(context(shown))?;
	#[cfg(test)]
	hook::opened(shown);
	let meta = handle.metadata()?;
	Ok(Node { handle, meta })
}

impl Node {
	/// Refuse a link, a special file, and, from the account, an entry it
	/// does not own or a file with another link.
	pub(crate) fn check(&self, shown: &Path, source: Source) -> io::Result<()> {
		let kind = self.meta.file_type();
		if kind.is_symlink() {
			return Err(io::Error::other(format!(
				"{} is a symbolic link; links are not followed",
				shown.display()
			)));
		}
		if !kind.is_file() && !kind.is_dir() {
			return Err(io::Error::other(format!(
				"{} is not a regular file or a directory; it is not copied",
				shown.display()
			)));
		}
		if let Source::Account(uid) = source {
			if self.meta.uid() != uid {
				return Err(io::Error::other(format!(
					"{} is not owned by the service account; it is not copied",
					shown.display()
				)));
			}
			if kind.is_file() && self.meta.nlink() != 1 {
				return Err(io::Error::other(format!(
					"{} has more than one hard link; it is not copied",
					shown.display()
				)));
			}
		}
		Ok(())
	}

	/// The directory itself, opened for listing through this descriptor.
	pub(crate) fn dir(self) -> io::Result<File> {
		self.reopen(libc::O_DIRECTORY)
	}

	/// The file itself, opened for reading through this descriptor.
	pub(crate) fn file(self) -> io::Result<File> {
		self.reopen(libc::O_NONBLOCK)
	}

	fn reopen(self, flags: i32) -> io::Result<File> {
		// The magic link names this descriptor's inode, not a path, so the
		// entry cannot be swapped between the fstat above and this open.
		let opened = OpenOptions::new()
			.read(true)
			.custom_flags(flags)
			.open(fd_path(&self.handle))?;
		let meta = opened.metadata()?;
		if (meta.dev(), meta.ino()) != (self.meta.dev(), self.meta.ino()) {
			return Err(io::Error::other(
				"an entry changed while it was being opened",
			));
		}
		Ok(opened)
	}
}

/// Create the directory `name` in `dir`, mode 0700, and open it.
pub(crate) fn make_dir(dir: &File, name: impl AsRef<Path>) -> io::Result<File> {
	let path = under(dir, name);
	DirBuilder::new().mode(0o700).create(&path)?;
	let node = open_node(&path, &path)?;
	// SAFETY: geteuid takes no arguments and cannot fail.
	if !node.meta.is_dir() || node.meta.uid() != unsafe { libc::geteuid() } {
		return Err(io::Error::other(format!(
			"{} changed while it was being created",
			path.display()
		)));
	}
	let opened = node.dir()?;
	opened.set_permissions(Permissions::from_mode(0o700))?;
	Ok(opened)
}

/// Create the new file `name` in `dir`, mode 0600. `O_EXCL` never follows
/// a link and never opens a file that was already there.
pub(crate) fn make_file(dir: &File, name: impl AsRef<Path>) -> io::Result<File> {
	let file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW)
		.open(under(dir, name))?;
	file.set_permissions(Permissions::from_mode(0o600))?;
	Ok(file)
}

/// Copy the regular file open as `source` into `dir` as `name`, mode 0600,
/// charging `budget`, then hand it over with `chown`.
pub(crate) fn copy_file(
	source: Node,
	shown: &Path,
	dir: &File,
	name: &Path,
	rel: &Path,
	budget: &mut Budget,
	chown: Chown,
) -> io::Result<()> {
	if source.meta.len() > budget.left {
		return Err(budget.exceeded());
	}
	let file = source.file().map_err(context(shown))?;
	let target = make_file(dir, name)?;
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
/// An entry [`Node::check`] refuses anywhere in the tree stops the copy.
pub(crate) fn copy_tree(
	source: &File,
	target: &File,
	shown: &Path,
	rel: &Path,
	budget: &mut Budget,
	chown: Chown,
) -> io::Result<()> {
	for entry in fs::read_dir(under(source, "")).map_err(context(shown))? {
		let name = PathBuf::from(entry?.file_name());
		let (shown, rel) = (shown.join(&name), rel.join(&name));
		let node = open_node(&under(source, &name), &shown)?;
		node.check(&shown, budget.source)?;
		if node.meta.is_dir() {
			let from = node.dir()?;
			let to = make_dir(target, &name)?;
			chown(&to, &rel)?;
			copy_tree(&from, &to, &shown, &rel, budget, chown)?;
		} else {
			copy_file(node, &shown, target, &name, &rel, budget, chown)?;
		}
	}
	Ok(())
}

/// Open `rel` below the directory open as `dir`, one component at a time,
/// each checked as coming from `source`.
pub(crate) fn open_beneath(dir: &File, rel: &Path, source: Source) -> io::Result<Node> {
	let mut current = dir.try_clone()?;
	let mut parts = rel.components().filter_map(|part| match part {
		Component::Normal(name) => Some(name),
		_ => None,
	});
	let mut next = parts.next();
	while let Some(part) = next {
		let node = open_node(&under(&current, part), rel)?;
		node.check(rel, source)?;
		next = parts.next();
		if next.is_none() {
			return Ok(node);
		}
		if !node.meta.is_dir() {
			return Err(io::Error::other(format!(
				"{} is not a directory",
				rel.display()
			)));
		}
		current = node.dir()?;
	}
	Err(io::Error::from(io::ErrorKind::InvalidInput))
}

/// Remove everything inside the directory open as `dir`. Each entry is
/// looked at through its own descriptor; a link is unlinked, never
/// followed, and `rmdir` and `unlink` act on the name, not on a target.
pub(crate) fn clear(dir: &File) -> io::Result<()> {
	for entry in fs::read_dir(under(dir, ""))? {
		let path = under(dir, entry?.file_name());
		let node = open_node(&path, &path)?;
		if node.meta.is_dir() {
			clear(&node.dir()?)?;
			fs::remove_dir(&path)?;
		} else {
			fs::remove_file(&path)?;
		}
	}
	Ok(())
}

/// A test hook run right after an entry is opened, before anything is
/// decided about it, to swap the entry under the copy.
#[cfg(test)]
pub(crate) mod hook {
	use std::cell::RefCell;
	use std::path::Path;

	type Hook = Box<dyn FnMut(&Path)>;

	thread_local! {
		static OPENED: RefCell<Option<Hook>> = RefCell::new(None);
	}

	/// Run `hook` with the shown path of every entry opened on this thread.
	pub(crate) fn set(hook: Option<Hook>) {
		OPENED.with(|cell| *cell.borrow_mut() = hook);
	}

	pub(super) fn opened(shown: &Path) {
		OPENED.with(|cell| {
			if let Some(hook) = cell.borrow_mut().as_mut() {
				hook(shown);
			}
		});
	}
}

#[cfg(test)]
#[path = "copy_tests.rs"]
mod tests;
