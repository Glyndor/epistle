//! The host-side restore temp file used by the container restore path.
//! The SQL bytes contain credential hashes, so the file lives in a directory
//! of its own created at mode `0700` and is itself created at mode `0600`
//! from the moment of creation, must not follow a hostile parent directory,
//! and must be removed on every exit path (success, error, panic). It lives
//! in its own file to keep `db_dump.rs` under the per-file code-line cap.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::BackupError;

/// The start of every staged name; the process id follows it.
pub(super) const PREFIX: &str = "epistle-restore-";

/// The name of the SQL file inside the private directory, on the host and
/// inside the container alike.
pub(super) const SQL_FILE_NAME: &str = "restore.sql";

/// A host-side restore temp file: a private directory made `0700` under a
/// name unique to this call, holding a file created `0600` with `O_EXCL` and
/// `O_NOFOLLOW`, written through the handle that created it, and removed on
/// `Drop`. `pub(super)` so the unit tests can inspect the modes and the
/// cleanup without spawning anything.
pub(super) struct RestoreHostTemp {
	dir: PathBuf,
	path: PathBuf,
	file: File,
}

impl RestoreHostTemp {
	/// Create an empty file at mode `0600` inside a new `0700` directory
	/// under [`std::env::temp_dir`] and return a handle ready to be written
	/// into.
	///
	/// The directory is made by `mkdir` with the mode in the call, so there
	/// is no moment at which it is more open than `0700`, and a name that is
	/// already taken (a directory, a file or a link planted by a name
	/// guesser) is skipped rather than followed. The name is built from the
	/// pid, the wall clock and the attempt counter.
	pub(super) fn create() -> Result<Self, BackupError> {
		let parent = std::env::temp_dir();
		remove_abandoned(&parent);
		Self::create_in(&parent, &|attempt| {
			format!(
				"{PREFIX}{}-{}-{attempt}",
				std::process::id(),
				nanos_since_epoch(),
			)
		})
	}

	/// [`create`](Self::create) with the directory and the candidate names
	/// chosen by the caller, so a test can make the first candidate collide.
	fn create_in(parent: &Path, name_of: &dyn Fn(u64) -> String) -> Result<Self, BackupError> {
		for attempt in 0..1024_u64 {
			let dir = parent.join(name_of(attempt));
			match DirBuilder::new().mode(0o700).create(&dir) {
				Ok(()) => {}
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
				Err(error) => return Err(cannot(&dir, error)),
			}
			let path = dir.join(SQL_FILE_NAME);
			return match OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.custom_flags(libc::O_NOFOLLOW)
				.open(&path)
			{
				Ok(file) => Ok(Self { dir, path, file }),
				Err(error) => {
					let _ = std::fs::remove_dir(&dir);
					Err(cannot(&path, error))
				}
			};
		}
		Err(BackupError::CommandFailed {
			stderr: "restore temporary names are occupied".to_string(),
			code: None,
		})
	}

	/// The path of the SQL file.
	pub(super) fn path(&self) -> &Path {
		&self.path
	}

	/// The private directory holding the SQL file.
	#[cfg(test)]
	pub(super) fn dir(&self) -> &Path {
		&self.dir
	}

	/// The name of the private directory, so the caller can hand the
	/// container copy the same unique name.
	pub(super) fn file_name(&self) -> Result<String, BackupError> {
		self.dir
			.file_name()
			.map(|name| name.to_string_lossy().into_owned())
			.ok_or_else(|| BackupError::CommandFailed {
				stderr: format!("restore directory {} has no name", self.dir.display()),
				code: None,
			})
	}

	/// Write `sql` through the handle that created the file, so the bytes
	/// never reach a path somebody else could have swapped underneath.
	pub(super) fn write_all(&mut self, sql: &[u8]) -> Result<(), BackupError> {
		self.file
			.write_all(sql)
			.map_err(|error| cannot(&self.path, error))
	}

	/// Remove the file and its directory now, saying what is still there if
	/// that fails. `Drop` repeats the attempt, silently, as a backstop.
	pub(super) fn remove(&self) -> Result<(), String> {
		let file = std::fs::remove_file(&self.path);
		let dir = std::fs::remove_dir(&self.dir);
		match (file, dir) {
			(Ok(()), Ok(())) => Ok(()),
			(Err(error), _) if error.kind() != io::ErrorKind::NotFound => {
				Err(format!("{} on the host: {error}", self.path.display()))
			}
			(_, Err(error)) if error.kind() != io::ErrorKind::NotFound => {
				Err(format!("{} on the host: {error}", self.dir.display()))
			}
			_ => Ok(()),
		}
	}
}

impl Drop for RestoreHostTemp {
	fn drop(&mut self) {
		let _ = std::fs::remove_file(&self.path);
		let _ = std::fs::remove_dir(&self.dir);
	}
}

/// The process id inside a staged name (`epistle-restore-<pid>-...`), when
/// the name is one.
pub(super) fn staged_pid(name: &str) -> Option<i32> {
	name.strip_prefix(PREFIX)?.split('-').next()?.parse().ok()
}

/// Remove the staged directories an earlier restore left behind when a signal
/// killed it before its guard could run. The process id in the name tells
/// whether the restore that made it is still alive; only directories and
/// regular files of this user are touched, never a link, and a failure to
/// remove one is not a failure of the restore that is starting.
fn remove_abandoned(parent: &Path) {
	let Ok(entries) = std::fs::read_dir(parent) else {
		return;
	};
	// SAFETY: geteuid takes no arguments and cannot fail.
	let me = unsafe { libc::geteuid() };
	for entry in entries.flatten() {
		let name = entry.file_name();
		let Some(pid) = name.to_str().and_then(|name| {
			name.strip_prefix(PREFIX)?
				.split('-')
				.next()?
				.parse::<i32>()
				.ok()
		}) else {
			continue;
		};
		let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
			continue;
		};
		if removable(
			metadata.is_dir() || metadata.is_file(),
			metadata.uid(),
			me,
			process_alive(pid),
		) {
			// A directory of ours is emptied without following links; a
			// plain file (the shape an older version staged) is unlinked.
			if metadata.is_dir() {
				let _ = std::fs::remove_dir_all(entry.path());
			} else {
				let _ = std::fs::remove_file(entry.path());
			}
		}
	}
}

/// Whether a staged name found in a shared `$TMPDIR` is ours to remove: a
/// directory or regular file (never a link), owned by the user running this restore (a
/// file of somebody else with a name that looks like ours is not touched),
/// whose restore is gone.
fn removable(is_plain: bool, owner: u32, me: u32, restore_alive: bool) -> bool {
	is_plain && owner == me && !restore_alive
}

/// Whether a process with this id exists. A process of another user answers
/// `EPERM`, which still means it is there.
pub(super) fn process_alive(pid: i32) -> bool {
	// SAFETY: signal 0 only checks that the process exists.
	pid <= 0
		|| unsafe { libc::kill(pid, 0) } == 0
		|| io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// The clock reading the name off, in nanoseconds since the epoch. A
/// process that cannot read the clock (it is before the epoch, on a
/// filesystem mounted with a broken RTC) still gets a name from the pid and
/// the attempt counter, which the `O_EXCL` loop then makes unique.
fn nanos_since_epoch() -> u128 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|elapsed| elapsed.as_nanos())
		.unwrap_or(0)
}

fn cannot(path: &Path, error: io::Error) -> BackupError {
	BackupError::CommandFailed {
		stderr: format!("cannot write {}: {error}", path.display()),
		code: None,
	}
}

#[cfg(test)]
#[path = "db_dump_tests_host_temp.rs"]
mod tests;
