//! One lock for service edits, init reruns and stack configuration writers.
//!
//! Every writer of `mail.toml` or of the generated `compose.yaml` takes this
//! lock before it reads either file, so two commands can not read the same
//! state and write over each other. The wait has a deadline and says who is
//! holding the lock: a `podup` restart under the lock is normal, and an
//! operator watching a silent hang has no way to tell it from a crash.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

/// How long a writer waits for the lock before it gives up. Longer than the
/// slowest thing that holds it (a `podup` recreate of the mail service), so a
/// slow neighbour is not reported as a stuck one. The lock that guards the
/// generated compose file waits with it, so a command is never kept out of
/// the configuration directory longer than it waits for one file.
pub(super) const WAIT: Duration = Duration::from_secs(30);

/// Pause between attempts while a neighbour holds the lock.
pub(super) const POLL: Duration = Duration::from_millis(100);

/// Lock the configuration directory before reading either service file.
/// The sibling stays in place when mail.toml is atomically replaced.
pub(super) fn acquire(config: &Path) -> Result<File, String> {
	acquire_within(config, WAIT)
}

/// [`acquire`] with the deadline passed in, so a test does not have to wait a
/// full half minute to see the refusal. `within` only bounds the wait: a
/// caller that arrives first takes the lock immediately.
pub(super) fn acquire_within(config: &Path, within: Duration) -> Result<File, String> {
	let parent = config
		.parent()
		.filter(|p| !p.as_os_str().is_empty())
		.unwrap_or(Path::new("."));
	let path = parent.join(".epistle-config.lock");
	let file = open(&path)?;
	let metadata = file.metadata().map_err(|e| e.to_string())?;
	if !metadata.is_file() {
		return Err(format!("{} must be a regular lock file", path.display()));
	}
	// A lock this user owns is put back to the mode the writers create, so a
	// file another tool left wide (a `touch` under umask 002) does not refuse
	// every command from then on.
	if metadata.uid() == unsafe { libc::geteuid() } {
		file.set_permissions(fs::Permissions::from_mode(0o600))
			.map_err(|error| format!("cannot set the mode of {}: {error}", path.display()))?;
	}
	let metadata = file.metadata().map_err(|e| e.to_string())?;
	usable(&path, metadata.mode() & 0o7777, metadata.uid())?;
	wait_for(&file, &path, within)?;
	note_holder(&file);
	crate::cli::config_edit::announce_swept(&crate::cli::config_edit::sweep_orphans(parent));
	Ok(file)
}

/// Open the lock file, creating it when it is not there. A lock this user does
/// not own and can not write is opened read-only: `flock` serialises writers
/// through the descriptor alone, so a lock root created still excludes a second
/// command, and the holder record is then left to the owner to write.
fn open(path: &Path) -> Result<File, String> {
	let denied = |error: &std::io::Error| error.kind() == std::io::ErrorKind::PermissionDenied;
	let mut options = OpenOptions::new();
	options.read(true).write(true).create(true).truncate(false);
	#[cfg(unix)]
	{
		options
			.mode(0o600)
			.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	match options.open(path) {
		Ok(file) => Ok(file),
		Err(error) if denied(&error) => {
			let mut read_only = OpenOptions::new();
			read_only.read(true);
			#[cfg(unix)]
			{
				read_only.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
			}
			read_only
				.open(path)
				.map_err(|error| format!("cannot lock {}: {error}", path.display()))
		}
		Err(error) => Err(format!("cannot lock {}: {error}", path.display())),
	}
}

/// Whether a lock file is one this process may hold. The two owners an
/// installation has are the service user and root, who creates it from
/// `postinst` and takes it from the commands an operator runs under sudo; a
/// third one can not be taken over. The file carries no secret, so the only
/// mode refused is one that lets other users write it, where a third writer
/// could step in between the flock and the record.
fn usable(path: &Path, mode: u32, owner: u32) -> Result<(), String> {
	if owner != unsafe { libc::geteuid() } && owner != 0 {
		return Err(format!(
			"{} belongs to another user; remove it or run this command as its owner",
			path.display()
		));
	}
	if mode & 0o002 != 0 {
		return Err(format!(
			"{} is writable by other users ({mode:04o}); run `chmod 600 {}`",
			path.display(),
			path.display()
		));
	}
	Ok(())
}

/// Take the lock, waiting for the holder to finish and giving up at the
/// deadline. The wait is announced once, naming the holder, so an operator
/// watching the command knows what it is waiting for.
fn wait_for(file: &File, path: &Path, within: Duration) -> Result<(), String> {
	let deadline = Instant::now() + within;
	let mut announced = false;
	loop {
		match crate::storage::lock::flock_exclusive_nonblocking(file.as_raw_fd()) {
			Ok(()) => return Ok(()),
			Err(error) if error.raw_os_error() == Some(libc::EWOULDBLOCK) => {}
			Err(error) => return Err(format!("cannot lock {}: {error}", path.display())),
		}
		let holder = held_by(file);
		if !announced {
			announced = true;
			crate::cli::style::warn(match &holder {
				Some(holder) => format!(
					"{} is held by {holder}; waiting up to {}s for it to finish",
					path.display(),
					within.as_secs()
				),
				None => format!(
					"{} is held by another epistle command; waiting up to {}s for it to finish",
					path.display(),
					within.as_secs()
				),
			});
		}
		if Instant::now() >= deadline {
			return Err(match holder {
				Some(holder) => format!(
					"{holder} has held {} for longer than {}s; retry once it has finished",
					path.display(),
					within.as_secs()
				),
				None => format!(
					"another epistle command has held {} for longer than {}s; retry once it has finished",
					path.display(),
					within.as_secs()
				),
			});
		}
		std::thread::sleep(POLL);
	}
}

/// Record who holds the lock, so the next writer can name it in its wait
/// message. The file is empty before the first writer and after the last one
/// is killed; a half-written record reads as no holder, which is the safe
/// reading: the wait is announced without a name.
fn note_holder(file: &File) {
	let mut args = std::env::args();
	let program = args
		.next()
		.and_then(|arg| {
			Path::new(&arg)
				.file_name()
				.map(|name| name.to_string_lossy().into_owned())
		})
		.unwrap_or_else(|| "epistle".into());
	let command = std::iter::once(program)
		.chain(args)
		.collect::<Vec<_>>()
		.join(" ");
	let Ok(mut handle) = file.try_clone() else {
		return;
	};
	let record = format!("pid {}\n{command}\n", std::process::id());
	if handle.set_len(0).is_err() {
		return;
	}
	let _ = handle.seek(SeekFrom::Start(0));
	let _ = handle.write_all(record.as_bytes());
	let _ = handle.sync_all();
}

/// The holder recorded in `file`, as one line naming the process. `None` when
/// nothing is recorded or the record is not readable as one.
fn held_by(file: &File) -> Option<String> {
	let mut handle = file.try_clone().ok()?;
	handle.seek(SeekFrom::Start(0)).ok()?;
	let mut text = String::new();
	handle.read_to_string(&mut text).ok()?;
	let (pid, command) = text.split_once('\n')?;
	let pid = pid.trim().strip_prefix("pid ")?;
	let command = command.trim();
	if command.is_empty() {
		return None;
	}
	Some(format!("`{command}` (pid {pid})"))
}

#[cfg(test)]
#[path = "service_lock_tests.rs"]
mod tests;
