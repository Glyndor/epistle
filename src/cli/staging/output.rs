//! Move what the account's run wrote in the staging directory to where the
//! operator asked for it.
//!
//! The staging directory is the account's by then, so what is read there
//! must be the account's own (see [`copy::Source::Account`]). Where it is
//! written is the operator's: the requested path's directory is opened
//! once, and the output is created or checked through that descriptor,
//! never by its path again. When a directory on the requested path is
//! writable by others, they can still choose, while it is opened, where
//! that path leads; the output then lands only in a file or directory
//! this run created, or an empty one root owns, and stays 0600 or 0700
//! owned by root, so nobody else can read it there.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::copy::{self, Budget, Source};
use super::{Output, shown_parent};

/// The largest output file moved back: the import's password list, one
/// short line per new account.
const OUTPUT_FILE_LIMIT: u64 = super::table::FILE_LIMIT;

/// The directory of `requested`, opened (and created when `create`), and
/// the name `requested` has in it.
fn open_parent(requested: &Path, create: bool) -> io::Result<(File, PathBuf)> {
	let shown = requested.display();
	let name = requested
		.file_name()
		.map(PathBuf::from)
		.ok_or_else(|| io::Error::other(format!("{shown} names no file")))?;
	let parent = shown_parent(requested);
	if create {
		fs::create_dir_all(&parent)?;
	}
	let handle = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY)
		.open(&parent)
		.map_err(|error| {
			io::Error::new(
				error.kind(),
				format!("opening the directory of {shown}: {error}"),
			)
		})?;
	Ok((handle, name))
}

/// The account's output at `rel`, or `None` when the run wrote nothing
/// there (a dry run).
fn staged(stage: &File, rel: &Path, account: u32) -> io::Result<Option<copy::Node>> {
	match copy::open_beneath(stage, rel, Source::Account(account)) {
		Ok(node) => Ok(Some(node)),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(error),
	}
}

/// Move the password list to the requested path: a new file, mode 0600,
/// owned by this process (root). On any error nothing is left there.
pub(super) fn move_file(stage: &File, output: &Output, account: u32) -> io::Result<()> {
	let Some(node) = staged(stage, &output.rel, account)? else {
		return Ok(());
	};
	let shown = output.requested.display();
	if !node.meta.is_file() {
		return Err(io::Error::other(format!(
			"the output for {shown} is not a file"
		)));
	}
	if node.meta.len() > OUTPUT_FILE_LIMIT {
		return Err(io::Error::other(format!(
			"the output for {shown} is too large"
		)));
	}
	let source = node.file()?;
	let (parent, name) = open_parent(&output.requested, false)?;
	let target = copy::make_file(&parent, &name)
		.map_err(|error| io::Error::new(error.kind(), format!("writing {shown}: {error}")))?;
	let written = io::copy(
		&mut io::Read::take(&source, OUTPUT_FILE_LIMIT),
		&mut &target,
	)
	.and_then(|_| target.sync_all());
	if let Err(error) = written {
		let _ = fs::remove_file(copy::under(&parent, &name));
		return Err(io::Error::new(
			error.kind(),
			format!("writing {shown}: {error}"),
		));
	}
	Ok(())
}

/// Move an exported tree into the requested directory, created when
/// missing, which must be a directory owned by `root` and empty. The copy
/// is bounded by the room the target filesystem has (`room`). On any error
/// what was written there is removed again.
pub(super) fn move_dir(
	stage: &File,
	output: &Output,
	account: u32,
	root: u32,
	room: impl Fn(&File) -> io::Result<u64>,
) -> io::Result<()> {
	let Some(node) = staged(stage, &output.rel, account)? else {
		return Ok(());
	};
	let requested = &output.requested;
	let shown = requested.display();
	if !node.meta.is_dir() {
		return Err(io::Error::other(format!(
			"the output for {shown} is not a directory"
		)));
	}
	let source = node.dir()?;
	let (parent, name) = open_parent(requested, true)?;
	let created = match DirBuilder::new()
		.mode(0o700)
		.create(copy::under(&parent, &name))
	{
		Ok(()) => true,
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
		Err(error) => {
			return Err(io::Error::new(
				error.kind(),
				format!("creating {shown}: {error}"),
			));
		}
	};
	let target = copy::open_node(&copy::under(&parent, &name), requested)?;
	if target.meta.file_type().is_symlink() {
		return Err(io::Error::other(format!(
			"{shown} is a symbolic link; the export is not written through it"
		)));
	}
	if !target.meta.is_dir() || target.meta.uid() != root {
		return Err(io::Error::other(format!(
			"{shown} is not a directory owned by root; the export is not written into it"
		)));
	}
	let target = target.dir()?;
	if fs::read_dir(copy::under(&target, ""))?.next().is_some() {
		return Err(io::Error::other(format!(
			"{shown} is not empty; the export is not written into it"
		)));
	}
	let mut budget = Budget::free_space(room(&target)?, requested).written_by_account(account);
	let copied = copy::copy_tree(
		&source,
		&target,
		requested,
		Path::new(""),
		&mut budget,
		&|_, _| Ok(()),
	);
	if let Err(error) = copied {
		let _ = copy::clear(&target);
		if created {
			let _ = fs::remove_dir(copy::under(&parent, &name));
		}
		return Err(io::Error::new(
			error.kind(),
			format!("writing {shown}: {error}"),
		));
	}
	Ok(())
}

/// What a copy may add to the filesystem of `target`: its free space less
/// a margin, by `fstatvfs` on the descriptor.
pub(super) fn free_room(target: &File) -> io::Result<u64> {
	use std::os::unix::io::AsRawFd;
	// SAFETY: a zeroed statvfs is valid storage for fstatvfs's output.
	let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
	// SAFETY: the descriptor is open for the call and `stats` outlives it.
	if unsafe { libc::fstatvfs(target.as_raw_fd(), &mut stats) } != 0 {
		return Err(io::Error::last_os_error());
	}
	// The field types differ between targets; on 64-bit Linux they are u64.
	#[allow(clippy::unnecessary_cast)]
	let (block, available, total) = (
		(stats.f_frsize as u64).max(1),
		stats.f_bavail as u64,
		stats.f_blocks as u64,
	);
	Ok(room_for(
		available.saturating_mul(block),
		total.saturating_mul(block),
	))
}

/// Free space less 5% of the filesystem, the share kept so an export never
/// fills the disk it lands on (which may be the one the mail server writes
/// to). Nothing when the filesystem is already that full.
pub(super) fn room_for(available: u64, total: u64) -> u64 {
	available.saturating_sub(total / 20)
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
