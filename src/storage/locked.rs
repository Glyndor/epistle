//! Read-mutate-write helper shared by the four dynamic stores.
//!
//! The CLI and the running server are separate processes that mutate
//! the same files (`accounts.toml`, `app_passwords.toml`, `masked.json`,
//! `api_keys.toml`). Without serialisation, two callers can each load
//! the file before the other writes and one will overwrite the other's
//! update.
//!
//! [`edit`] takes an exclusive advisory lock on a sibling `.<name>.lock`
//! file, re-reads the data file from disk while holding it, hands the
//! fresh state to the closure, writes the result atomically through
//! [`crate::storage::write_secret`], and returns the post-write state.
//! The caller's in-memory mirror is refreshed by replacing it with the
//! returned value — that is what makes a sibling process's write visible
//! without a server restart.
//!
//! Readers do not need the lock: atomic renames mean an in-flight
//! reader either sees the old or the new version, never a mix.

use std::path::{Path, PathBuf};

use crate::storage::lock::FileLock;
use crate::storage::write_secret;

/// What [`edit`] can fail with: an `io::Error` for filesystem-level
/// problems (lock acquisition, read, parse, write) and the closure's
/// own error type for validation or rule violations raised under the
/// lock.
#[derive(Debug)]
pub enum EditError<E> {
	/// Locking, reading, parsing, serialising or writing failed.
	Io(std::io::Error),
	/// The `mutate` closure rejected the change.
	Mutate(E),
}

impl<E: std::fmt::Display> std::fmt::Display for EditError<E> {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Io(error) => write!(formatter, "{error}"),
			Self::Mutate(error) => write!(formatter, "{error}"),
		}
	}
}

impl<E: std::error::Error + 'static> std::error::Error for EditError<E> {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			Self::Mutate(error) => Some(error),
		}
	}
}

impl<E> From<std::io::Error> for EditError<E> {
	fn from(error: std::io::Error) -> Self {
		Self::Io(error)
	}
}

impl<E: std::fmt::Display> From<EditError<E>> for std::io::Error {
	fn from(error: EditError<E>) -> Self {
		match error {
			EditError::Io(io) => io,
			EditError::Mutate(other) => std::io::Error::other(other.to_string()),
		}
	}
}

/// Take the exclusive `flock` on `path`, re-read it from disk, hand the
/// fresh state to `mutate`, write atomically, and return the post-write
/// state. `parse` reads the on-disk text; `serialize` produces the
/// new text; `default` is the empty/in-memory state for a missing
/// file (the normal "first run" case).
///
/// The closure runs while the lock is held, so its validation sees
/// the latest committed state: a name-collision check under the lock
/// catches the case where the CLI added an account between the
/// server's last read and its own write attempt.
pub fn edit<T, E, F>(
	path: &Path,
	parse: impl Fn(&str) -> std::io::Result<T>,
	serialize: impl Fn(&T) -> std::io::Result<String>,
	default: impl Fn() -> T,
	mutate: F,
) -> Result<T, EditError<E>>
where
	F: FnOnce(&mut T) -> Result<(), E>,
{
	edit_and_commit(path, parse, serialize, default, mutate, |state| state)
}

/// [`edit`], plus a `commit` step that receives the post-write state
/// while the lock is still held. A caller whose in-memory mirror is
/// shared between threads (`&self` mutators) replaces it in `commit`:
/// replacing it after the lock is released would let a second writer
/// commit and refresh in between, and the first writer's late refresh
/// would roll the mirror back to the older state.
pub fn edit_and_commit<T, E, F, R>(
	path: &Path,
	parse: impl Fn(&str) -> std::io::Result<T>,
	serialize: impl Fn(&T) -> std::io::Result<String>,
	default: impl Fn() -> T,
	mutate: F,
	commit: impl FnOnce(T) -> R,
) -> Result<R, EditError<E>>
where
	F: FnOnce(&mut T) -> Result<(), E>,
{
	let _lock = FileLock::acquire(&lock_path(path))?;
	let mut state = match std::fs::read_to_string(path) {
		Ok(text) => parse(&text)?,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => default(),
		Err(error) => return Err(error.into()),
	};
	mutate(&mut state).map_err(EditError::Mutate)?;
	let text = serialize(&state).map_err(EditError::Io)?;
	write_secret(path, text.as_bytes())?;
	Ok(commit(state))
}

/// Sibling lock path used by [`edit`]: `.<name>.lock` in the same
/// directory, so the lock lives and dies with the data file.
pub(crate) fn lock_path(path: &Path) -> PathBuf {
	let parent = path
		.parent()
		.filter(|p| !p.as_os_str().is_empty())
		.unwrap_or(Path::new("."));
	let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("store");
	parent.join(format!(".{name}.lock"))
}
