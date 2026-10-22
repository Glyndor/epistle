//! Descriptor-relative access to private migration progress files.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

/// The name of the lock file inside one account's state directory.
pub(super) const LOCK: &str = ".lock";

fn name(value: &std::ffi::OsStr) -> io::Result<CString> {
	CString::new(value.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput.into())
}

fn owned(file: &File, directory: bool) -> io::Result<()> {
	// SAFETY: geteuid has no arguments or memory access requirements.
	let uid = unsafe { libc::geteuid() };
	owned_by(file, directory, uid)
}

fn owned_by(file: &File, directory: bool, uid: u32) -> io::Result<()> {
	let metadata = file.metadata()?;
	if metadata.uid() != uid
		|| if directory {
			!metadata.is_dir()
		} else {
			!metadata.is_file() || metadata.nlink() != 1
		} {
		return Err(io::Error::other(
			"migration data_dir and state must be owned by the effective user and have the expected file type",
		));
	}
	Ok(())
}

fn open_at(dir: &File, child: &CString, flags: i32) -> io::Result<File> {
	// SAFETY: dir is open, child is a live C string, and mode is supplied for O_CREAT.
	let fd = unsafe {
		libc::openat(
			dir.as_raw_fd(),
			child.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
			0o600,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	// SAFETY: openat returned a new descriptor owned only by this File.
	Ok(unsafe { File::from_raw_fd(fd) })
}

/// Resolve parent links once, then open the root without following links.
pub(super) fn root(path: &Path) -> io::Result<File> {
	let open = || -> io::Result<File> {
		if path
			.components()
			.any(|part| matches!(part, Component::ParentDir))
		{
			return Err(io::Error::other(
				"migration root must not contain parent components",
			));
		}
		// Components remove trailing separators and dots before checking the final name.
		let normalized: std::path::PathBuf = path.components().collect();
		if std::fs::symlink_metadata(&normalized)?
			.file_type()
			.is_symlink()
		{
			return Err(io::Error::other(
				"migration data_dir must not be a symbolic link",
			));
		}
		// Resolve parents, keeping the final name for the O_NOFOLLOW open below.
		let resolved = match normalized.file_name() {
			Some(child) => normalized
				.parent()
				.filter(|parent| !parent.as_os_str().is_empty())
				.unwrap_or(Path::new("."))
				.canonicalize()?
				.join(child),
			None => normalized.canonicalize()?,
		};
		let mut dir = std::fs::OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
			.open("/")?;
		for component in resolved.components() {
			if let Component::Normal(child) = component {
				dir = open_at(&dir, &name(child)?, libc::O_RDONLY | libc::O_DIRECTORY)?;
			}
		}
		owned(&dir, true)?;
		Ok(dir)
	};
	open().map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))
}

/// Open every state directory without following links. Create private children only for a save.
pub(super) fn directory(root: &File, account: &str, create: bool) -> io::Result<File> {
	let mut dir = root.try_clone()?;
	for child in ["migrate", account] {
		let child = name(child.as_ref())?;
		if create {
			// SAFETY: dir is open and child is a live C string with one component.
			let result = unsafe { libc::mkdirat(dir.as_raw_fd(), child.as_ptr(), 0o700) };
			if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
				return Err(io::Error::last_os_error());
			}
			super::durability::sync(&dir, "state-parent")?;
		}
		dir = open_at(&dir, &child, libc::O_RDONLY | libc::O_DIRECTORY)?;
		owned(&dir, true)?;
	}
	Ok(dir)
}

/// Open an existing regular state file owned by the current effective user.
pub(super) fn read(dir: &File, path: &Path) -> io::Result<File> {
	let child = name(path.file_name().ok_or(io::ErrorKind::InvalidInput)?)?;
	let file = open_at(dir, &child, libc::O_RDONLY)?;
	owned(&file, false)?;
	Ok(file)
}

/// Open an existing regular state file for appending records, without
/// following links.
pub(super) fn appendable(dir: &File, path: &Path) -> io::Result<File> {
	let child = name(path.file_name().ok_or(io::ErrorKind::InvalidInput)?)?;
	let file = open_at(dir, &child, libc::O_RDWR)?;
	owned(&file, false)?;
	Ok(file)
}

/// Open the lock file of one account's state directory, creating the
/// directory and the file when `create`. The descriptor is what holds the
/// lock: closing it releases the flock.
pub(super) fn lock_file(root: &File, account: &str, create: bool) -> io::Result<File> {
	let dir = directory(root, account, create)?;
	let file = open_at(&dir, &name(OsStr::new(LOCK))?, libc::O_RDWR | libc::O_CREAT)?;
	owned(&file, false)?;
	Ok(file)
}

struct Temporary<'a> {
	dir: &'a File,
	name: CString,
}

impl Drop for Temporary<'_> {
	fn drop(&mut self) {
		// SAFETY: both the directory descriptor and the C string outlive this call.
		unsafe {
			libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
		}
	}
}

/// Replace state using an exclusive private temporary in the open directory.
/// The two names the durability hooks see let the caller tell which file it is.
pub(super) fn replace(
	dir: &File,
	path: &Path,
	body: &[u8],
	file_kind: &'static str,
	dir_kind: &'static str,
) -> io::Result<()> {
	match read(dir, path) {
		Ok(_) => {}
		Err(error) if error.kind() == io::ErrorKind::NotFound => {}
		Err(error) => return Err(error),
	}
	let temporary_name = name(format!(".{}.tmp", uuid::Uuid::now_v7()).as_ref())?;
	let mut file = open_at(
		dir,
		&temporary_name,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
	)?;
	let temporary = Temporary {
		dir,
		name: temporary_name,
	};
	owned(&file, false)?;
	file.write_all(body)?;
	super::durability::sync(&file, file_kind)?;
	let child = name(path.file_name().ok_or(io::ErrorKind::InvalidInput)?)?;
	// SAFETY: both names are live C strings relative to the same open directory.
	let result = unsafe {
		libc::renameat(
			dir.as_raw_fd(),
			temporary.name.as_ptr(),
			dir.as_raw_fd(),
			child.as_ptr(),
		)
	};
	if result < 0 {
		return Err(io::Error::last_os_error());
	}
	super::durability::sync(dir, dir_kind)
}

#[cfg(test)]
#[path = "state_files_tests.rs"]
mod tests;

/// Create a private scratch file and unlink its name before returning the descriptor.
pub(super) fn scratch(dir: &File) -> io::Result<File> {
	let child = name(format!(".{}.index", uuid::Uuid::now_v7()).as_ref())?;
	let file = open_at(dir, &child, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?;
	let temporary = Temporary { dir, name: child };
	owned(&file, false)?;
	// SAFETY: the descriptor and C string remain live for the unlink.
	if unsafe { libc::unlinkat(dir.as_raw_fd(), temporary.name.as_ptr(), 0) } < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(file)
}
