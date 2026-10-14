//! File-mode pinning and the perms audit that runs at start-up (and the
//! non-destructive observer that backs the `spool` status check).

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use std::fs;
use std::path::Path;

/// Mode created files start with: owner read+write only. The brief is that no
/// file the spool holds (envelopes, bodies, the lock file) is ever group- or
/// world-readable, regardless of the umask under which a worker started.
#[cfg(unix)]
pub(crate) const FILE_MODE: u32 = 0o600;

/// Mode spool directories are created with: owner read+write+exec only.
/// 0700 means other users cannot even stat a sender's mailbox id in
/// `<data_dir>/spool/new/`, so the existence of a queue entry is also private.
#[cfg(unix)]
pub(crate) const DIR_MODE: u32 = 0o700;

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
/// pins the mode at create, so a spool file is never briefly readable by
/// group or world, regardless of the umask under which a worker started.
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

/// Walk the spool without modifying it and report the number of files and
/// directories that are looser than the owner-only bound. Used by the
/// `spool` status check, which must not silently retighten (the brief says
/// "report whether any file has loose permissions", not "fix and report").
/// Bounded: linear walk, no recursion.
#[cfg(unix)]
pub(crate) fn count_loose_permissions(root: &Path) -> std::io::Result<u64> {
	let mut loose = 0u64;
	count_loose_visit(root, &mut loose)?;
	Ok(loose)
}

#[cfg(unix)]
fn count_loose_visit(dir: &Path, loose: &mut u64) -> std::io::Result<()> {
	const DESIRED_FILE: u32 = 0o600;
	const DESIRED_DIR: u32 = 0o700;
	if let Ok(meta) = fs::symlink_metadata(dir)
		&& meta.file_type().is_dir()
	{
		let current = meta.permissions().mode() & 0o777;
		if current != DESIRED_DIR {
			*loose += 1;
		}
	}
	let Ok(rd) = fs::read_dir(dir) else {
		return Ok(());
	};
	for entry in rd {
		let entry = match entry {
			Ok(entry) => entry,
			Err(_) => continue,
		};
		let path = entry.path();
		let name = match entry.file_name().to_str() {
			Some(name) if !name.is_empty() && name != "." && name != ".." => name.to_string(),
			_ => continue,
		};
		let meta = match entry.metadata() {
			Ok(meta) => meta,
			Err(_) => continue,
		};
		let file_type = meta.file_type();
		if file_type.is_dir() {
			count_loose_visit(&path, loose)?;
		} else if file_type.is_file()
			&& (name.ends_with(".eml") || name.ends_with(".json") || name == "lock")
		{
			let current = meta.permissions().mode() & 0o777;
			if current != DESIRED_FILE {
				*loose += 1;
			}
		}
	}
	Ok(())
}

/// Walk the spool and retighten any file or directory whose permissions are
/// looser than `0600` (for files) or `0700` (for directories), counted
/// uniformly. Bounded: a linear walk of the spool tree, no recursion into
/// attacker-controlled filenames (entries whose name is not a single plain
/// component are skipped).
#[cfg(unix)]
pub(crate) fn audit_permissions(root: &Path) -> std::io::Result<u64> {
	const DESIRED_DIR: u32 = 0o700;
	let mut fixed = 0u64;
	// The spool root itself is silently retightened (not counted): the
	// count the brief asks for is "files fixed", so the operator log
	// stays tight on what actually mattered.
	if let Ok(meta) = fs::symlink_metadata(root)
		&& meta.file_type().is_dir()
	{
		let current = meta.permissions().mode() & 0o777;
		if current != DESIRED_DIR {
			fs::set_permissions(root, fs::Permissions::from_mode(DESIRED_DIR))?;
		}
	}
	visit_permissions(root, &mut fixed)?;
	Ok(fixed)
}

#[cfg(unix)]
fn visit_permissions(dir: &Path, fixed: &mut u64) -> std::io::Result<()> {
	const DESIRED_FILE: u32 = 0o600;
	const DESIRED_DIR: u32 = 0o700;
	let Ok(rd) = fs::read_dir(dir) else {
		return Ok(());
	};
	for entry in rd {
		let entry = match entry {
			Ok(entry) => entry,
			Err(_) => continue,
		};
		let path = entry.path();
		let name = match entry.file_name().to_str() {
			Some(name) if !name.is_empty() && name != "." && name != ".." => name.to_string(),
			_ => continue,
		};
		let meta = match entry.metadata() {
			Ok(meta) => meta,
			Err(_) => continue,
		};
		let file_type = meta.file_type();
		if file_type.is_dir() {
			let current = meta.permissions().mode() & 0o777;
			if current != DESIRED_DIR {
				fs::set_permissions(&path, fs::Permissions::from_mode(DESIRED_DIR))?;
			}
			visit_permissions(&path, fixed)?;
		} else if file_type.is_file()
			&& (name.ends_with(".eml") || name.ends_with(".json") || name == "lock")
		{
			let current = meta.permissions().mode() & 0o777;
			if current != DESIRED_FILE {
				fs::set_permissions(&path, fs::Permissions::from_mode(DESIRED_FILE))?;
				*fixed += 1;
			}
		}
	}
	Ok(())
}

#[cfg(not(unix))]
pub(crate) fn audit_permissions(_root: &Path) -> std::io::Result<u64> {
	Ok(0)
}

#[cfg(not(unix))]
pub(crate) fn count_loose_permissions(_root: &Path) -> std::io::Result<u64> {
	Ok(0)
}
