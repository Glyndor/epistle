//! Where the core listens for the HTTP fronts.
//!
//! Each surface listener of a stack that runs fronts is a Unix socket in a
//! directory of its own, `<home>/fronts/<name>/core.sock`, where `<home>` is the
//! parent of `data_dir`. The front mounts that one directory and nothing else,
//! so the mount is what says which surface a connection is for.

use std::path::{Path, PathBuf};

use crate::config::ListenerKind;

/// The file name of the socket inside its directory.
pub const SOCKET_NAME: &str = "core.sock";

/// The directory that holds every front's directory.
pub fn root(data_dir: &Path) -> PathBuf {
	data_dir
		.parent()
		.unwrap_or_else(|| Path::new("/"))
		.join("fronts")
}

/// Make [`root`], `0700`, when nobody made it yet. The stack creates it before
/// `mail` starts.
pub fn create_root(data_dir: &Path) -> std::io::Result<()> {
	use std::os::unix::fs::DirBuilderExt;
	std::fs::DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(root(data_dir))
}

/// The directory of the front for `kind`, which is the only thing that front
/// mounts.
pub fn dir(data_dir: &Path, kind: ListenerKind) -> PathBuf {
	root(data_dir).join(kind.as_str())
}

/// The socket of the front for `kind`.
pub fn path(data_dir: &Path, kind: ListenerKind) -> PathBuf {
	dir(data_dir, kind).join(SOCKET_NAME)
}
