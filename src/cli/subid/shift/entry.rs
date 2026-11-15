//! Opening an entry of the tree and changing it through that descriptor.
//!
//! The walk runs as root over directories that other ids can still rename
//! into. Every entry is therefore opened once, with `O_PATH | O_NOFOLLOW`,
//! relative to the root directory and with symbolic links refused in every
//! component before the last one. Owner, mode and attributes are then read
//! and written through that descriptor (`/proc/self/fd/N` names the opened
//! inode, not a path), so a name that changes afterwards leads nowhere.

use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The descriptor's name under `/proc/self/fd`, which resolves to the inode
/// it holds.
pub(super) fn proc_path(fd: BorrowedFd<'_>) -> PathBuf {
	PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
	std::ffi::CString::new(path.as_os_str().as_bytes())
		.map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// Open `root` itself, a link as the link, or `None` when it is missing.
pub(super) fn open_root(root: &Path) -> io::Result<Option<OwnedFd>> {
	let path = c_path(root)?;
	// SAFETY: `path` is NUL-terminated and outlives the call.
	let fd = unsafe {
		libc::open(
			path.as_ptr(),
			libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if fd >= 0 {
		// SAFETY: `open` returned a descriptor that nothing else owns.
		return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
	}
	let error = io::Error::last_os_error();
	if error.kind() == io::ErrorKind::NotFound {
		Ok(None)
	} else {
		Err(error)
	}
}

/// Open `relative` below the directory `base`. A symbolic link in any
/// component but the last is refused, the last one is opened as the link,
/// and `..` cannot leave `base`.
pub(super) fn open_below(base: BorrowedFd<'_>, relative: &Path) -> io::Result<OwnedFd> {
	let path = c_path(relative)?;
	// SAFETY: `open_how` is plain integers, for which all zeroes is valid.
	let mut how: libc::open_how = unsafe { std::mem::zeroed() };
	how.flags = (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
	how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
	// SAFETY: `path` is NUL-terminated and `how` is valid for the size passed.
	let fd = unsafe {
		libc::syscall(
			libc::SYS_openat2,
			base.as_raw_fd(),
			path.as_ptr(),
			&how,
			std::mem::size_of::<libc::open_how>(),
		)
	};
	if fd >= 0 {
		// SAFETY: the syscall returned a descriptor that nothing else owns.
		return Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) });
	}
	let error = io::Error::last_os_error();
	if error.raw_os_error() == Some(libc::ELOOP) {
		return Err(io::Error::other(
			"a component of the path is a symbolic link, which is not followed",
		));
	}
	Err(error)
}

/// What `fstat` says about the descriptor.
pub(super) fn stat(fd: BorrowedFd<'_>) -> io::Result<Metadata> {
	File::from(fd.try_clone_to_owned()?).metadata()
}

/// Change owner and group of the inode behind `fd`, which may be a link.
/// `None` keeps the current id.
pub(super) fn chown(fd: BorrowedFd<'_>, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
	// SAFETY: the empty path is NUL-terminated; with `AT_EMPTY_PATH` the call
	// acts on `fd` itself.
	let rc = unsafe {
		libc::fchownat(
			fd.as_raw_fd(),
			c"".as_ptr(),
			uid.unwrap_or(u32::MAX),
			gid.unwrap_or(u32::MAX),
			libc::AT_EMPTY_PATH,
		)
	};
	if rc == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}

/// Set the permission bits of the inode behind `fd`, which is not a link.
pub(super) fn chmod(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
	let path = c_path(&proc_path(fd))?;
	// SAFETY: `path` is NUL-terminated and outlives the call.
	let rc = unsafe { libc::chmod(path.as_ptr(), mode) };
	if rc == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}
