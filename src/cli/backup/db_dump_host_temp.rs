//! The host-side restore temp file used by the container restore path.
//! The SQL bytes contain credential hashes, so the file must be created at
//! mode `0600` from the moment of creation, must not follow a hostile
//! parent directory, and must be removed on every exit path (success,
//! error, panic). It lives in its own file to keep `db_dump.rs` under the
//! per-file code-line cap.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::BackupError;

/// The start of every staged name; the process id follows it.
const PREFIX: &str = "epistle-restore-";

/// A host-side restore temp file: created `0600` with `O_EXCL` and
/// `O_NOFOLLOW` under a name unique to this call, written through the
/// handle that created it, and removed on `Drop`. `pub(super)` so the unit
/// tests can inspect the mode and the cleanup without spawning anything.
pub(super) struct RestoreHostTemp {
	path: PathBuf,
	file: File,
}

impl RestoreHostTemp {
	/// Create an empty temp file under [`std::env::temp_dir`] at mode `0600`
	/// and return a handle ready to be written into.
	///
	/// `O_EXCL` plus a name built from the pid, the wall clock and the
	/// attempt counter keeps a name guesser from pre-creating the path: the
	/// open fails instead of following whatever is already there, and the
	/// loop moves to the next candidate. `O_NOFOLLOW` keeps a symlink at the
	/// name from redirecting the write.
	pub(super) fn create() -> Result<Self, BackupError> {
		let parent = std::env::temp_dir();
		remove_abandoned(&parent);
		Self::create_in(&parent, &|attempt| {
			format!(
				"{PREFIX}{}-{}-{attempt}.sql",
				std::process::id(),
				nanos_since_epoch(),
			)
		})
	}

	/// [`create`](Self::create) with the directory and the candidate names
	/// chosen by the caller, so a test can make the first candidate collide.
	fn create_in(parent: &Path, name_of: &dyn Fn(u64) -> String) -> Result<Self, BackupError> {
		for attempt in 0..1024_u64 {
			let path = parent.join(name_of(attempt));
			match OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.custom_flags(libc::O_NOFOLLOW)
				.open(&path)
			{
				Ok(file) => return Ok(Self { path, file }),
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
				Err(error) => return Err(cannot(&path, error)),
			}
		}
		Err(BackupError::CommandFailed {
			stderr: "restore temporary names are occupied".to_string(),
			code: None,
		})
	}

	/// The path the file lives at.
	pub(super) fn path(&self) -> &Path {
		&self.path
	}

	/// The file name alone, so the caller can hand the container copy the
	/// same unique name.
	pub(super) fn file_name(&self) -> String {
		self.path
			.file_name()
			.map(|name| name.to_string_lossy().into_owned())
			.unwrap_or_default()
	}

	/// Write `sql` through the handle that created the file, so the bytes
	/// never reach a path somebody else could have swapped underneath.
	pub(super) fn write_all(&mut self, sql: &[u8]) -> Result<(), BackupError> {
		self.file
			.write_all(sql)
			.map_err(|error| cannot(&self.path, error))
	}
}

impl Drop for RestoreHostTemp {
	fn drop(&mut self) {
		let _ = std::fs::remove_file(&self.path);
	}
}

/// Remove the staged files an earlier restore left behind when a signal
/// killed it before its guard could run. The process id in the name tells
/// whether the restore that made it is still alive; only regular files of
/// this user are touched, never a link, and a failure to remove one is not
/// a failure of the restore that is starting.
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
				.strip_suffix(".sql")?
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
		if removable(metadata.is_file(), metadata.uid(), me, process_alive(pid)) {
			let _ = std::fs::remove_file(entry.path());
		}
	}
}

/// Whether a staged name found in a shared `$TMPDIR` is ours to remove: a
/// regular file (never a link), owned by the user running this restore (a
/// file of somebody else with a name that looks like ours is not touched),
/// whose restore is gone.
fn removable(is_file: bool, owner: u32, me: u32, restore_alive: bool) -> bool {
	is_file && owner == me && !restore_alive
}

/// Whether a process with this id exists. A process of another user answers
/// `EPERM`, which still means it is there.
fn process_alive(pid: i32) -> bool {
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
