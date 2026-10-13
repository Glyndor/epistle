//! Persistent per-mailbox UIDVALIDITY (RFC 3501 §2.3.1.1).
//!
//! A constant value is written to `.uidvalidity` on first open so clients can
//! trust cached UIDs across sessions; it changes only if the mailbox is
//! recreated (the sidecar is gone).

use crate::util::path_component::{StateFile, state_file, state_tmp_file};
use std::path::Path;

/// Read the mailbox's UIDVALIDITY, initializing it on first open. The value
/// comes from [`allocate`] and is persisted in `.uidvalidity`.
pub(super) fn read_or_init(account_dir: &Path, account_root: &Path) -> u32 {
	let path = state_file(account_dir, StateFile::UidValidity);
	if let Ok(path) = &path
		&& let Some(value) = read(path)
	{
		return value;
	}
	// A mailbox without a directory yet (an INBOX that never received mail)
	// keeps nothing, so it takes the clock and records no allocation.
	if !account_dir.is_dir() {
		return clock();
	}
	let value = allocate(account_root);
	if let Ok(path) = &path {
		let _ = std::fs::write(path, value.to_string());
	}
	value
}

/// A UIDVALIDITY this account has not handed out before: seconds since the
/// epoch forced odd (never 0), or two past the last value when the clock has
/// not moved past it. A mailbox deleted and created again within the same
/// second must not get its old value back, or a client would keep UIDs that
/// now name other messages. The last value lives in the account root, which
/// outlives any one mailbox.
fn allocate(account_root: &Path) -> u32 {
	let now = clock();
	let last = state_file(account_root, StateFile::UidValidityLast)
		.ok()
		.and_then(|path| read(&path));
	let value = match last {
		Some(last) if last >= now => last.checked_add(2).unwrap_or(now),
		_ => now,
	};
	if let (Ok(tmp), Ok(path)) = (
		state_tmp_file(account_root, StateFile::UidValidityLast),
		state_file(account_root, StateFile::UidValidityLast),
	) && std::fs::write(&tmp, value.to_string()).is_ok()
	{
		let _ = std::fs::rename(tmp, path);
	}
	value
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
