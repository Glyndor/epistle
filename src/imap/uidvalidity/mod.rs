//! Persistent per-mailbox UIDVALIDITY (RFC 3501 §2.3.1.1).
//!
//! A constant value is written to `.uidvalidity` on first open so clients can
//! trust cached UIDs across sessions; it changes only if the mailbox is
//! recreated (the sidecar is gone).

use crate::util::path_component::{AccountRoot, FixedDir, StateFile, state_file, state_tmp_file};
use std::path::Path;

/// Read the mailbox's UIDVALIDITY, initializing it on first open. The value
/// comes from [`allocate`] and is persisted in `.uidvalidity`.
///
/// Allocation runs under an exclusive lock on the account's
/// `.uidvalidity_lock`, so two sessions creating mailboxes at the same moment
/// never get the same value, and two sessions opening one new mailbox agree
/// on the value the first of them wrote.
pub(super) fn read_or_init(account_dir: &Path, account_root: &AccountRoot) -> u32 {
	let Ok(path) = state_file(account_dir, StateFile::UidValidity) else {
		return clock();
	};
	if let Some(value) = read(&path) {
		return value;
	}
	// A mailbox without a directory yet (an INBOX that never received mail)
	// keeps nothing, so it takes the clock and records no allocation.
	if !account_dir.is_dir() {
		return clock();
	}
	// Without the lock nothing is recorded, so the next open allocates again.
	let Ok(_lock) = lock(account_root) else {
		return clock();
	};
	if let Some(value) = read(&path) {
		return value;
	}
	let value = allocate(account_root);
	// The counter goes first: a crash between the two writes leaves it ahead
	// of the mailbox, never behind.
	if write(account_root.as_path(), StateFile::UidValidityLast, value).is_ok() {
		let _ = write(account_dir, StateFile::UidValidity, value);
	}
	value
}

/// A UIDVALIDITY this account has not handed out before: seconds since the
/// epoch forced odd (never 0), or two past the highest value already used
/// when the clock has not moved past it. "Already used" is the last value
/// recorded in the account root, which outlives any one mailbox, and the
/// value of every mailbox that exists now, so a lost or damaged counter
/// cannot send values back below one in use. A mailbox deleted and created
/// again within the same second must not get its old value back, or a client
/// would keep UIDs that now name other messages. Caller holds the lock.
fn allocate(account_root: &AccountRoot) -> u32 {
	let now = clock();
	let last = state_file(account_root.as_path(), StateFile::UidValidityLast)
		.ok()
		.and_then(|path| read(&path));
	let highest = last.into_iter().chain(in_use(account_root)).max();
	match highest {
		Some(highest) if highest >= now => highest.checked_add(2).unwrap_or(now),
		_ => now,
	}
}

/// The UIDVALIDITY of INBOX and of every folder that has one.
fn in_use(account_root: &AccountRoot) -> Vec<u32> {
	let mut dirs = Vec::new();
	if let Ok(inbox) = account_root.child(FixedDir::New) {
		dirs.push(inbox);
	}
	if let Ok(folders) = account_root.child(FixedDir::Folders)
		&& let Ok(entries) = crate::util::fs_walk::read_dir(&folders)
	{
		dirs.extend(entries.flatten().map(|entry| entry.path().join("new")));
	}
	dirs.iter()
		.filter_map(|dir| state_file(dir, StateFile::UidValidity).ok())
		.filter_map(|path| read(&path))
		.collect()
}

fn lock(account_root: &AccountRoot) -> std::io::Result<std::fs::File> {
	let file = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.open(state_file(
			account_root.as_path(),
			StateFile::UidValidityLock,
		)?)?;
	file.lock()?;
	Ok(file)
}

/// Replace `file` in `dir` with `value` in one rename, so a reader sees the
/// old value or the new one and never a partial write.
fn write(dir: &Path, file: StateFile, value: u32) -> std::io::Result<()> {
	let tmp = state_tmp_file(dir, file)?;
	std::fs::write(&tmp, value.to_string())?;
	std::fs::rename(tmp, state_file(dir, file)?)
}

fn clock() -> u32 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as u32)
		.unwrap_or(1)
		| 1
}

fn read(path: &Path) -> Option<u32> {
	let text = crate::util::fs_walk::read_to_string(path).ok()?;
	text.trim().parse::<u32>().ok().filter(|value| *value > 0)
}

#[cfg(test)]
mod tests;
