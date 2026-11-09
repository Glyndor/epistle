//! Directory durability for the spool: a rename is only durable once the
//! directory that holds the new name has been synced.

use std::path::Path;

/// Sync the directory that holds a published file's name.
///
/// The file's own sync makes its bytes durable, but the name it is
/// published under lives in the directory that holds it, and that entry is
/// what a power cut takes back: without this sync the file can come back
/// under its previous name, and a message the remote already answered for
/// comes back pending and is sent again.
///
/// Unix only: on other targets there is nothing to sync and the call does
/// nothing, so the code still compiles.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
	use std::fs;
	fs::File::open(dir)?.sync_all()
}

/// [`sync_dir`] where there is no directory to sync.
#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> std::io::Result<()> {
	Ok(())
}

/// Sync the directory that holds `path`'s name, so the rename that
/// published the file under that name is durable.
pub(crate) fn sync_dir_of(path: &Path) -> std::io::Result<()> {
	match path.parent() {
		Some(dir) => sync_dir(dir),
		None => Ok(()),
	}
}
