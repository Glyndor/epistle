//! File-mode pinning and the perms audit that runs at start-up (and the
//! non-destructive observer that backs the `spool` status check).

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use std::fs;
use std::path::Path;

/// Mode created files start with: owner read+write only. No file the spool
/// holds (envelopes, bodies, the lock file) is ever group- or
/// world-readable, regardless of the umask under which a worker started.
#[cfg(unix)]
pub(crate) const FILE_MODE: u32 = 0o600;

/// Mode spool directories are created with: owner read+write+exec only.
/// 0700 means other users cannot even stat a sender's mailbox id in
/// `<data_dir>/spool/new/`, so the existence of a queue entry is also private.
#[cfg(unix)]
pub(crate) const DIR_MODE: u32 = 0o700;

/// The spool's fixed subdirectories. The audit and the status count look at
/// the root, these two and the files directly inside the three, nothing else.
#[cfg(unix)]
const SUBDIRS: [&str; 2] = ["tmp", "new"];

/// Create the spool root directory (if missing) along with its `tmp/` and
/// `new/` children, all at mode 0700. The mode is pinned at create time:
/// `DirBuilder::mode(0o700)` plus `DirBuilder::recursive(true)` so missing
/// parents are created, so the resulting tree is owner-only regardless of
/// the process umask.
pub(crate) fn create_spool_dir(root: &Path) -> std::io::Result<()> {
	let mut builder = fs::DirBuilder::new();
	builder.recursive(true);
	#[cfg(unix)]
	builder.mode(DIR_MODE);
	builder.create(root)?;
	for child in ["tmp", "new"] {
		let mut child_builder = fs::DirBuilder::new();
		child_builder.recursive(true);
		#[cfg(unix)]
		child_builder.mode(DIR_MODE);
		child_builder.create(root.join(child))?;
	}
	Ok(())
}

/// Write `bytes` to `path` and fsync the file before returning.
///
/// The file is created at mode `0600` from the start: `OpenOptions::mode`
/// pins the mode at create, so a spool file is never readable by group or
/// world at any point, regardless of the umask under which a worker started.
pub(crate) fn write_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
	let mut options = fs::OpenOptions::new();
	options.write(true).create(true).truncate(true);
	#[cfg(unix)]
	options.mode(FILE_MODE);
	let mut file = options.open(path)?;
	use std::io::Write;
	file.write_all(bytes)?;
	file.sync_all()
}

/// What a spool path is expected to be.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
	File,
	Dir,
}

/// Count the spool paths whose mode is not owner-only, without changing
/// anything. Used by the `spool` status check, which observes the on-disk
/// state rather than fixing it.
#[cfg(unix)]
pub(crate) fn count_loose_permissions(root: &Path) -> std::io::Result<u64> {
	let (dirs, files) = walk(root, false)?;
	Ok(dirs + files)
}

/// Retighten every spool directory looser than `0700` and every spool file
/// looser than `0600`, and return how many files were changed. Directories
/// are retightened too but not counted, so the start-up log reports the
/// files that held mail data.
#[cfg(unix)]
pub(crate) fn audit_permissions(root: &Path) -> std::io::Result<u64> {
	let (_, files) = walk(root, true)?;
	Ok(files)
}

/// Visit the root, its fixed subdirectories and the `.eml`, `.json` and
/// `lock` files directly inside them, and return how many directories and
/// files were loose (and retightened when `apply`). Bounded by the number of
/// entries in three directories; links and special files are skipped, and
/// nothing is changed unless it is owned by the owner of the spool root.
#[cfg(unix)]
fn walk(root: &Path, apply: bool) -> std::io::Result<(u64, u64)> {
	let Ok(meta) = fs::symlink_metadata(root) else {
		return Ok((0, 0));
	};
	if !meta.is_dir() {
		return Ok((0, 0));
	}
	let owner = meta.uid();
	let (mut dirs, mut files) = (0u64, 0u64);
	let tree = std::iter::once(root.to_path_buf()).chain(SUBDIRS.iter().map(|name| root.join(name)));
	for dir in tree {
		if retighten(&dir, Kind::Dir, owner, apply)? {
			dirs += 1;
		}
		let Ok(entries) = fs::read_dir(&dir) else {
			continue;
		};
		for entry in entries.flatten() {
			if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
				continue;
			}
			let name = entry.file_name();
			let Some(name) = name.to_str() else {
				continue;
			};
			if !(name.ends_with(".eml") || name.ends_with(".json") || name == "lock") {
				continue;
			}
			if retighten(&entry.path(), Kind::File, owner, apply)? {
				files += 1;
			}
		}
	}
	Ok((dirs, files))
}

/// Whether `path` is a `kind` owned by `owner` with a mode other than the
/// owner-only one, setting that mode when `apply`. The path is opened with
/// `O_NOFOLLOW` and checked and changed through the open descriptor, so an
/// entry replaced by a link after the listing cannot redirect the change.
#[cfg(unix)]
pub(super) fn retighten(path: &Path, kind: Kind, owner: u32, apply: bool) -> std::io::Result<bool> {
	let mut options = fs::OpenOptions::new();
	options.read(true);
	let mut flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
	if kind == Kind::Dir {
		flags |= libc::O_DIRECTORY;
	}
	options.custom_flags(flags);
	let file = match options.open(path) {
		Ok(file) => file,
		// A link, a vanished entry, or something that is not a directory
		// where one was listed: not a spool path to change.
		Err(error)
			if matches!(
				error.raw_os_error(),
				Some(libc::ELOOP | libc::ENOENT | libc::ENOTDIR)
			) =>
		{
			return Ok(false);
		}
		Err(error) => return Err(error),
	};
	let meta = file.metadata()?;
	let (matches, desired) = match kind {
		Kind::File => (meta.is_file(), FILE_MODE),
		Kind::Dir => (meta.is_dir(), DIR_MODE),
	};
	if !matches || meta.uid() != owner || meta.mode() & 0o777 == desired {
		return Ok(false);
	}
	if apply {
		file.set_permissions(fs::Permissions::from_mode(desired))?;
	}
	Ok(true)
}

#[cfg(not(unix))]
pub(crate) fn audit_permissions(_root: &Path) -> std::io::Result<u64> {
	Ok(0)
}

#[cfg(not(unix))]
pub(crate) fn count_loose_permissions(_root: &Path) -> std::io::Result<u64> {
	Ok(0)
}
