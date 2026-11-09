//! Persistent IMAP UIDs (RFC 3501 §2.3.1.1).
//!
//! Each message's UID is stored in a `<id>.uid` sidecar, assigned from the
//! mailbox's monotonic counter in `.uidnext` on first sight. Unlike positional
//! UIDs, these stay stable across expunges and sessions, which clients rely on.
//!
//! The counter and the sidecars are shared by every scan of the mailbox, so
//! the assignment runs under an advisory lock on `.uid_lock`: two scans at the
//! same time would otherwise hand the same UID to two different messages,
//! which RFC 3501 §2.3.1.1 forbids.

use std::path::Path;

use crate::util::path_component::{
	MessageExt, StateFile, message_file, message_tmp_file, state_file, state_tmp_file,
};
use uuid::Uuid;

/// The UID persisted for `id`, or `None` if it has not been assigned yet.
pub(super) fn read_message(account_dir: &Path, id: Uuid) -> Option<u32> {
	message_file(account_dir, id, MessageExt::Uid)
		.and_then(crate::util::fs_walk::read_to_string)
		.ok()
		.and_then(|text| text.trim().parse().ok())
}

/// Persist `uid` as message `id`'s UID.
pub(super) fn write_message(account_dir: &Path, id: Uuid, uid: u32) -> std::io::Result<()> {
	let tmp = message_tmp_file(account_dir, id, MessageExt::Uid)?;
	std::fs::write(&tmp, uid.to_string())?;
	std::fs::rename(&tmp, message_file(account_dir, id, MessageExt::Uid)?)
}

/// The mailbox UID counter (`.uidnext`), 0 when absent (no UID assigned yet).
pub(super) fn read_counter(account_dir: &Path) -> u32 {
	state_file(account_dir, StateFile::UidNext)
		.and_then(crate::util::fs_walk::read_to_string)
		.ok()
		.and_then(|text| text.trim().parse().ok())
		.unwrap_or(0)
}

/// Persist the mailbox UID counter.
pub(super) fn write_counter(account_dir: &Path, value: u32) -> std::io::Result<()> {
	let tmp = state_tmp_file(account_dir, StateFile::UidNext)?;
	std::fs::write(&tmp, value.to_string())?;
	std::fs::rename(&tmp, state_file(account_dir, StateFile::UidNext)?)
}

/// The UID of every message in `ids`, in that order, assigning the ones that
/// have none yet.
///
/// The UIDs already persisted are read first without any lock: a mailbox
/// whose messages all have a UID is only read, and the lock is never taken.
/// When some message has none, the mailbox's UID lock is taken, the counter
/// and the missing UIDs are read again under it — a sibling scan may have
/// assigned some of them in the meantime — and the ones still missing are
/// assigned from that counter, in the order given.
pub(super) fn resolve_uids(account_dir: &Path, ids: &[Uuid]) -> Vec<u32> {
	let mut uids: Vec<Option<u32>> = ids
		.iter()
		.map(|id| read_message(account_dir, *id))
		.collect();
	if uids.iter().all(Option::is_some) {
		return uids.into_iter().flatten().collect();
	}
	// At least one message has no UID: the assignment is serialised with the
	// other scans of this mailbox, so two of them never hand out the same
	// UID.
	let _guard = match lock(account_dir) {
		Ok(file) => Some(file),
		Err(error) => {
			// The lock cannot be taken: the assignment goes on without it,
			// as it did before, and two scans of this mailbox can race.
			tracing::warn!(
				%error,
				mailbox = %crate::log_id::path(account_dir),
				"could not take the mailbox UID lock; assigning UIDs without it"
			);
			None
		}
	};
	let mut counter = read_counter(account_dir);
	let mut assigned = false;
	for (id, uid) in ids.iter().zip(uids.iter_mut()) {
		if uid.is_some() {
			continue;
		}
		if let Some(existing) = read_message(account_dir, *id) {
			*uid = Some(existing);
			continue;
		}
		counter += 1;
		let _ = write_message(account_dir, *id, counter);
		*uid = Some(counter);
		assigned = true;
	}
	if assigned {
		let _ = write_counter(account_dir, counter);
	}
	uids.into_iter().flatten().collect()
}

/// Take the mailbox's UID lock: an exclusive advisory lock on `.uid_lock`,
/// released when the returned file is dropped.
fn lock(account_dir: &Path) -> std::io::Result<std::fs::File> {
	let file = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.open(state_file(account_dir, StateFile::UidLock)?)?;
	file.lock()?;
	Ok(file)
}

#[cfg(test)]
mod tests;
