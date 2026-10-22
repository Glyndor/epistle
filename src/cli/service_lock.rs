//! One lock for service edits, init reruns and stack configuration writers.
//!
//! Every writer of `mail.toml` or of the generated `compose.yaml` takes this
//! lock before it reads either file, so two commands can not read the same
//! state and write over each other. The wait has a deadline and says who is
//! holding the lock: a `podup` restart under the lock is normal, and an
//! operator watching a silent hang has no way to tell it from a crash.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

/// How long a writer waits for the lock before it gives up. Longer than the
/// slowest thing that holds it (a `podup` recreate of the mail service), so a
/// slow neighbour is not reported as a stuck one.
const WAIT: Duration = Duration::from_secs(30);

/// Pause between attempts while a neighbour holds the lock.
const POLL: Duration = Duration::from_millis(100);

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
	let file = OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.truncate(false)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
		.open(&path)
		.map_err(|e| format!("cannot lock {}: {e}", path.display()))?;
	let metadata = file.metadata().map_err(|e| e.to_string())?;
	if !metadata.is_file() {
		return Err(format!("{} must be a regular lock file", path.display()));
	}
	usable(&path, metadata.mode() & 0o7777, metadata.uid())?;
	wait_for(&file, &path, within)?;
	note_holder(&file);
	crate::cli::config_edit::announce_swept(&crate::cli::config_edit::sweep_orphans(parent));
	Ok(file)
}

/// Whether a lock file is one this process may hold: a regular file of this
/// user, in one of the two modes the writers agree on. `0644` is accepted
/// because a lock file carries no secret and the service user has to be able
/// to take a lock root created; anything wider is refused, with the mode the
/// file has, so the operator knows what to change.
fn usable(path: &Path, mode: u32, owner: u32) -> Result<(), String> {
	if !matches!(mode, 0o600 | 0o644) {
		return Err(format!(
			"{} must be mode 0600 or 0644, not {mode:04o}",
			path.display()
		));
	}
	// Another owner can not be taken over: writing our own record into a
	// file we do not own would fail later, in the middle of the lock.
	if owner != unsafe { libc::geteuid() } {
		return Err(format!(
			"{} belongs to another user; remove it or run this command as its owner",
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
