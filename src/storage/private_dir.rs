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
/// umask of the process that made it. Only `path` itself is tightened
/// when it already exists with a looser mode: a parent that was there
/// before is left as it is, one created here is `0700`.
///
/// `path` must be `root` joined with plain names, and `root` is chosen by
/// the trusted caller: a missing `root` is created `0700` with its parents.
/// The root is resolved once; the part of `path` below it is walked one
/// name at a time. A `..`, an absolute tail or a NUL in a name is refused.
/// A missing name is created with `mkdir`, which never follows a link, and
/// a name that already exists is resolved and must still start with the
/// resolved root and be a real directory. A link leading out of `root`
/// fails with `InvalidInput`, and the filesystem calls only ever see a
/// value derived from the checked one.
pub(crate) fn create_private_dir(root: &Path, path: &Path) -> io::Result<()> {
	make_dir_all(root)?;
	let root_resolved = root.canonicalize()?;
	let tail = path.strip_prefix(root).map_err(|_| escapes_root())?;
	let mut current = root_resolved.clone();
	for component in tail.components() {
		let name = match component {
			Component::CurDir => continue,
			Component::Normal(name) if !name.to_string_lossy().contains('\0') => name,
			_ => return Err(escapes_root()),
		};
		current = step(&root_resolved, &current, name)?;
	}
	tighten(&current)
}

/// One name below the checked directory `parent`: a freshly created `0700`
/// directory, or the resolved existing entry.
fn step(root: &Path, parent: &Path, name: &std::ffi::OsStr) -> io::Result<PathBuf> {
	let next = parent.join(name);
	match make_dir(&next) {
		Ok(()) => return Ok(next),
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
		Err(error) => return Err(error),
	}
	// It exists: possibly a plain directory, possibly a link, and possibly
	// one a concurrent writer has just made. Resolve it again and trust only
	// the result. A link that dangles has nothing to resolve.
	let resolved = match next.canonicalize() {
		Ok(resolved) => resolved,
		Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(escapes_root()),
		Err(error) => return Err(error),
	};
	if !resolved.starts_with(root) {
		return Err(escapes_root());
	}
	if !resolved.symlink_metadata()?.is_dir() {
		return Err(io::Error::from(io::ErrorKind::AlreadyExists));
	}
	Ok(resolved)
}

/// `path` and its missing parents, `0700`, without any containment check:
/// only for the root, which the trusted caller chose.
fn make_dir_all(path: &Path) -> io::Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	builder.recursive(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	builder.create(path)
}

/// One directory, `0700`, failing with `AlreadyExists` when the name is taken
/// by anything, a link included.
fn make_dir(path: &Path) -> io::Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	builder.create(path)
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
