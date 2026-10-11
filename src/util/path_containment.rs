//! The one place that decides whether a path built under a root directory
//! still lies inside it.
//!
//! Account names, mailbox names, message ids and digest names are already
//! validated one component at a time (see [`super::path_component`]). That
//! validation is local to each type, so a bug in any one of them, or a
//! symlink planted inside the data directory, would let a join walk out of
//! the tree without anything downstream noticing. [`contained`] is the
//! check every join goes through, independent of those validators:
//!
//! 1. The part of the path that exists is resolved with
//!    [`Path::canonicalize`], so `..` components and symlinks are replaced by
//!    the real location before anything is compared.
//! 2. The part that does not exist yet (a mailbox about to be created, a
//!    spool file about to be written) may only be made of plain names, none
//!    of which contains `..`. Nothing can be resolved there, so nothing
//!    traversing is allowed there.
//! 3. The resolved path must start with the resolved root, otherwise the
//!    call fails and no path is returned.

use std::io;
use std::path::{Component, Path, PathBuf};

/// The error for a path that is not inside its root.
fn escapes_root() -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidInput,
		"path is not inside its root directory",
	)
}

/// The error for a path that could not be resolved. It keeps the kind of the
/// underlying failure so callers can still tell `NotFound` or a permission
/// problem apart, and leaves the path itself out of the message.
fn unresolvable(error: &io::Error) -> io::Error {
	io::Error::new(
		error.kind(),
		"cannot resolve a path under its root directory",
	)
}

/// Append the not-yet-existing `tail` to the resolved `base`, accepting plain
/// names only: `.` is skipped, and `..`, roots, prefixes, non-UTF-8 names and
/// any name containing `..` are refused.
fn append_plain(mut base: PathBuf, tail: &Path) -> io::Result<PathBuf> {
	for component in tail.components() {
		match component {
			Component::CurDir => {}
			Component::Normal(name) => {
				let Some(name) = name.to_str() else {
					return Err(escapes_root());
				};
				if name.contains("..") {
					return Err(escapes_root());
				}
				base.push(name);
			}
			_ => return Err(escapes_root()),
		}
	}
	Ok(base)
}

/// `path` with every existing component resolved (symlinks and `..` gone)
/// and the missing tail, if any, appended under [`append_plain`]'s rules.
fn resolve(path: &Path) -> io::Result<PathBuf> {
	let mut existing = path;
	loop {
		let probe = if existing.as_os_str().is_empty() {
			Path::new(".")
		} else {
			existing
		};
		match probe.canonicalize() {
			Ok(base) => {
				let Ok(tail) = path.strip_prefix(existing) else {
					return Err(escapes_root());
				};
				return append_plain(base, tail);
			}
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				let Some(parent) = existing.parent() else {
					return Err(escapes_root());
				};
				existing = parent;
			}
			Err(error) => return Err(error),
		}
	}
}

/// Return the resolved form of `candidate` if, and only if, it lies inside
/// `root`.
///
/// `candidate` is normally `root` joined with validated components, so for
/// well-formed input this only costs the resolution. It fails with
/// [`io::ErrorKind::InvalidInput`] when a join escapes through `..` or
/// through a symlink, and with the I/O error of the resolution when the
/// filesystem cannot be read. Callers must use the returned path, not the
/// one they passed in.
///
/// The resolved paths are matched on rather than propagated with `?`: the
/// value that reaches the caller must be the one the `starts_with` test below
/// was applied to, never an early return that skips it.
pub fn contained(root: &Path, candidate: &Path) -> io::Result<PathBuf> {
	let root = match resolve(root) {
		Ok(resolved) => resolved,
		Err(error) => return Err(unresolvable(&error)),
	};
	let resolved = match resolve(candidate) {
		Ok(resolved) => resolved,
		Err(error) => return Err(unresolvable(&error)),
	};
	if resolved.starts_with(&root) {
		Ok(resolved)
	} else {
		Err(escapes_root())
	}
}

#[cfg(test)]
#[path = "path_containment_tests.rs"]
mod tests;
