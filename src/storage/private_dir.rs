use std::io;
use std::path::{Component, Path, PathBuf};

fn escapes_root() -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidInput,
		"path is not inside its root directory",
	)
}

/// Create `path` and its missing parents with owner-only (`0700`)
/// permissions.
///
/// The mode is pinned at create time (`DirBuilder::mode`), so the
/// directory is never briefly readable by another user whatever the
/// umask of the process that made it, and a directory left behind by an
/// earlier deploy is tightened on the next write. The same shape
/// `src/storage/spool` uses for the mailbox tree.
///
/// `path` must be `root` joined with plain names. The root is resolved
/// once; the part of `path` below it is walked one name at a time, each
/// existing step is resolved and must still start with the resolved
/// root, and a missing step is created under the already checked parent.
/// A `..` component, an absolute tail or a link leading out of `root`
/// fails with `InvalidInput`, and the filesystem calls only ever see a
/// value derived from the checked one.
pub(crate) fn create_private_dir(root: &Path, path: &Path) -> io::Result<()> {
	let root_resolved = root.canonicalize()?;
	let tail = path.strip_prefix(root).map_err(|_| escapes_root())?;
	let mut current = root_resolved.clone();
	for component in tail.components() {
		let name = match component {
			Component::CurDir => continue,
			Component::Normal(name) if name.to_str().is_some_and(|n| !n.contains("..")) => name,
			_ => return Err(escapes_root()),
		};
		current = step(&root_resolved, &current, name)?;
	}
	if !current.is_dir() {
		return Err(io::Error::from(io::ErrorKind::AlreadyExists));
	}
	tighten(&current)
}

/// One name below the checked directory `parent`: the resolved existing
/// entry, or a freshly created `0700` directory.
fn step(root: &Path, parent: &Path, name: &std::ffi::OsStr) -> io::Result<PathBuf> {
	let next = parent.join(name);
	match next.canonicalize() {
		Ok(resolved) if resolved.starts_with(root) => Ok(resolved),
		Ok(_) => Err(escapes_root()),
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			// A dangling link has no target to resolve and must not be followed.
			if next.symlink_metadata().is_ok() {
				return Err(escapes_root());
			}
			make_dir(&next)?;
			Ok(next)
		}
		Err(error) => Err(error),
	}
}

fn make_dir(path: &Path) -> io::Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	match builder.create(path) {
		Err(error) if error.kind() != io::ErrorKind::AlreadyExists => Err(error),
		_ => Ok(()),
	}
}

fn tighten(path: &Path) -> io::Result<()> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let metadata = std::fs::metadata(path)?;
		if metadata.permissions().mode() & 0o777 != 0o700 {
			std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
		}
	}
	#[cfg(not(unix))]
	let _ = path;
	Ok(())
}
