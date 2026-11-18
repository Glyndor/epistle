//! Binding the signer's socket with permissions only its own uid passes.

use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

use tokio::net::UnixListener;

/// The mode of the directory that holds the socket.
const DIR_MODE: u32 = 0o700;
/// The mode of the socket itself.
const SOCKET_MODE: u32 = 0o600;

/// Bind the signer's socket at `path`, inside a directory only this uid
/// can enter.
///
/// The parent directory is created `0700` when it is missing. When it
/// exists it must be a real directory (not a symlink), owned by the
/// effective uid, with no permission for group or others; otherwise the
/// bind is refused. A socket left at `path` by an earlier run is removed;
/// anything else at `path` is refused, never removed. The socket is
/// `0600` once bound. Between the bind and that `chmod` the directory is
/// what keeps other uids out. Must run inside a Tokio runtime.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
	let dir = path
		.parent()
		.filter(|dir| !dir.as_os_str().is_empty())
		.ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::InvalidInput,
				"the signer socket path names no directory",
			)
		})?;
	private_directory(dir)?;
	remove_stale_socket(path)?;
	let listener = UnixListener::bind(path)?;
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
	Ok(listener)
}

/// Create `dir` with [`DIR_MODE`], or check that the existing one is a
/// directory of this uid that nobody else can enter.
fn private_directory(dir: &Path) -> io::Result<()> {
	let meta = match std::fs::symlink_metadata(dir) {
		Ok(meta) => meta,
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			std::fs::DirBuilder::new().mode(DIR_MODE).create(dir)?;
			std::fs::symlink_metadata(dir)?
		}
		Err(error) => return Err(error),
	};
	if !meta.file_type().is_dir() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!(
				"the signer socket directory {} is not a directory",
				dir.display()
			),
		));
	}
	// SAFETY: geteuid has no preconditions and cannot fail.
	let euid = unsafe { libc::geteuid() };
	if meta.uid() != euid || meta.mode() & 0o077 != 0 {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			format!(
				"the signer socket directory {} must be owned by uid {euid} and closed to group and others (0700)",
				dir.display()
			),
		));
	}
	Ok(())
}

/// Remove a socket an earlier run left at `path`. Anything that is not a
/// socket stays, and the bind is refused.
fn remove_stale_socket(path: &Path) -> io::Result<()> {
	match std::fs::symlink_metadata(path) {
		Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
		Ok(_) => Err(io::Error::new(
			io::ErrorKind::AlreadyExists,
			format!(
				"{} exists and is not a socket; it is left in place",
				path.display()
			),
		)),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(error),
	}
}
