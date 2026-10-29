//! The two system calls every staging decision rests on, issued directly so
//! that neither the C library nor std can change what they do.
//!
//! Measured on the musl build the Debian package ships: std masks custom
//! open flags with `!O_ACCMODE`, and musl's `O_ACCMODE` includes `O_PATH`
//! (its `O_SEARCH`), so `O_PATH` was dropped without a word. Opening a link
//! then failed with ELOOP and opening a socket with ENXIO, while the glibc
//! build passed every test. `statx` is issued directly too, so the
//! descriptor's own inode is what gets described, whatever a C library's
//! `fstat` does with an `O_PATH` descriptor.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

/// `struct statx` from the kernel's `linux/stat.h`. Its layout is the same
/// on every architecture, unlike `struct stat`.
#[repr(C)]
#[derive(Default)]
struct Statx {
	mask: u32,
	blksize: u32,
	attributes: u64,
	nlink: u32,
	uid: u32,
	gid: u32,
	mode: u16,
	spare0: u16,
	ino: u64,
	size: u64,
	blocks: u64,
	attributes_mask: u64,
	/// atime, btime, ctime and mtime, 16 bytes each.
	times: [u64; 8],
	rdev_major: u32,
	rdev_minor: u32,
	dev_major: u32,
	dev_minor: u32,
	spare: [u64; 14],
}

/// `STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_GID |
/// STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_INO | STATX_SIZE |
/// STATX_BLOCKS`.
const STATX_BASIC_STATS: u32 = 0x7ff;

/// What `statx` says about an open descriptor: the fields staging decides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stat {
	mode: u32,
	uid: u32,
	nlink: u32,
	size: u64,
	ino: u64,
	dev: (u32, u32),
}

impl Stat {
	fn kind(&self) -> u32 {
		self.mode & libc::S_IFMT
	}

	pub(crate) fn is_dir(&self) -> bool {
		self.kind() == libc::S_IFDIR
	}

	pub(crate) fn is_file(&self) -> bool {
		self.kind() == libc::S_IFREG
	}

	pub(crate) fn is_symlink(&self) -> bool {
		self.kind() == libc::S_IFLNK
	}

	pub(crate) fn uid(&self) -> u32 {
		self.uid
	}

	pub(crate) fn nlink(&self) -> u32 {
		self.nlink
	}

	pub(crate) fn len(&self) -> u64 {
		self.size
	}

	pub(crate) fn mode(&self) -> u32 {
		self.mode
	}

	/// Whether `other` describes the same inode.
	pub(crate) fn same_inode(&self, other: &Stat) -> bool {
		(self.dev, self.ino) == (other.dev, other.ino)
	}
}

/// `statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)`: the descriptor's
/// own inode, never what it might point to.
pub(crate) fn of(file: &File) -> io::Result<Stat> {
	let mut out = Statx::default();
	// SAFETY: the descriptor is open for the call, the path is a valid empty
	// C string, and `out` is a writable `struct statx` that outlives it.
	let result = unsafe {
		libc::syscall(
			libc::SYS_statx,
			file.as_raw_fd(),
			c"".as_ptr(),
			libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
			STATX_BASIC_STATS,
			&mut out as *mut Statx,
		)
	};
	if result != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(Stat {
		mode: u32::from(out.mode),
		uid: out.uid,
		nlink: out.nlink,
		size: out.size,
		ino: out.ino,
		dev: (out.dev_major, out.dev_minor),
	})
}

/// `openat(AT_FDCWD, at, O_PATH | O_NOFOLLOW | O_CLOEXEC)`: a descriptor for
/// the entry itself, a link as the link, with no side effect on a device.
pub(crate) fn open_path(at: &Path) -> io::Result<File> {
	let path = CString::new(at.as_os_str().as_bytes())
		.map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
	let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
	// SAFETY: the path is a valid C string that outlives the call; the
	// mode argument is ignored without O_CREAT.
	let fd = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path.as_ptr(), flags, 0) };
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	let fd = i32::try_from(fd).map_err(|_| io::Error::other("descriptor out of range"))?;
	// SAFETY: the kernel just returned this descriptor and nothing else owns it.
	Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests;
