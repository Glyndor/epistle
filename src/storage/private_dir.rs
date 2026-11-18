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
/// the trusted caller: a missing `root` is created `0700` with its parents,
/// one name at a time below its deepest existing ancestor.
/// The root is resolved once; the part of `path` below it is walked one
/// name at a time. A `..`, an absolute tail or a NUL in a name is refused.
/// A missing name is created with `mkdir`, which never follows a link, and
/// a name that already exists is resolved and must still start with the
/// resolved root and be a real directory. A link leading out of `root`
/// fails with `InvalidInput`, and the filesystem calls only ever see a
/// value derived from the checked one.
pub(crate) fn create_private_dir(root: &Path, path: &Path) -> io::Result<()> {
	let root_resolved = bootstrap_root(root)?;
	let tail = path.strip_prefix(root).map_err(|_| escapes_root())?;
	let current = walk_names(&root_resolved, root_resolved.clone(), tail)?;
	tighten(&root_resolved, &current)
}

/// Walk the plain names of `tail` down from the checked directory `start`,
/// creating the missing ones, and return the last directory.
fn walk_names(root: &Path, start: PathBuf, tail: &Path) -> io::Result<PathBuf> {
	let mut current = start;
	for component in tail.components() {
		let name = match component {
			Component::CurDir => continue,
			Component::Normal(name) if !name.to_string_lossy().contains('\0') => name,
			_ => return Err(escapes_root()),
		};
		current = step(root, &current, name)?;
	}
	Ok(current)
}

/// The resolved `root`, created `0700` when missing.
///
/// `root` is chosen by the trusted caller. The part that exists is resolved
/// once; the missing names below it are then created one at a time under
/// that resolved ancestor, with the same checks as any other name.
fn bootstrap_root(root: &Path) -> io::Result<PathBuf> {
	let mut existing = root;
	let base = loop {
		match existing.canonicalize() {
			Ok(resolved) => break resolved,
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				existing = existing.parent().ok_or_else(escapes_root)?;
			}
			Err(error) => return Err(error),
		}
	};
	let tail = root.strip_prefix(existing).map_err(|_| escapes_root())?;
	walk_names(&base, base.clone(), tail)
}

/// One name below the checked directory `parent`: a freshly created `0700`
/// directory, or the resolved existing entry.
fn step(root: &Path, parent: &Path, name: &std::ffi::OsStr) -> io::Result<PathBuf> {
	let parent = parent.canonicalize()?;
	if !parent.starts_with(root) {
		return Err(escapes_root());
	}
	let next = parent.join(name);
	if !next.starts_with(root) {
		return Err(escapes_root());
	}
	match make_dir(&next) {
		Ok(()) => {
			// Created by `mkdir`, which never follows a link: resolve it and
			// trust only the result.
			let created = next.canonicalize()?;
			if !created.starts_with(root) {
				return Err(escapes_root());
			}
			return Ok(created);
		}
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

/// Set `path`, which lies under `root`, to `0700`; only the resolved and
/// checked value reaches the filesystem calls.
fn tighten(root: &Path, path: &Path) -> io::Result<()> {
	let checked = path.canonicalize()?;
	if !checked.starts_with(root) {
		return Err(escapes_root());
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let metadata = std::fs::metadata(&checked)?;
		if metadata.permissions().mode() & 0o777 != 0o700 {
			std::fs::set_permissions(&checked, std::fs::Permissions::from_mode(0o700))?;
		}
	}
	Ok(())
}
