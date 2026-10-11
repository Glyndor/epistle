//! Persistent IMAP UIDs (RFC 3501 §2.3.1.1).
//!
//! Each message's UID is stored in a `<id>.uid` sidecar, assigned from the
//! mailbox's monotonic counter in `.uidnext` on first sight. Unlike positional
//! UIDs, these stay stable across expunges and sessions, which clients rely on.

use std::path::Path;

use crate::util::path_component::{
	MessageExt, StateFile, message_file, message_tmp_file, state_file, state_tmp_file,
};
use uuid::Uuid;

/// The UID persisted for `id`, or `None` if it has not been assigned yet.
pub(super) fn read_message(account_dir: &Path, id: Uuid) -> Option<u32> {
	crate::util::fs_walk::read_to_string(message_file(account_dir, id, MessageExt::Uid))
		.ok()
		.and_then(|text| text.trim().parse().ok())
}

/// Persist `uid` as message `id`'s UID.
pub(super) fn write_message(account_dir: &Path, id: Uuid, uid: u32) -> std::io::Result<()> {
	let tmp = message_tmp_file(account_dir, id, MessageExt::Uid);
	std::fs::write(&tmp, uid.to_string())?;
	std::fs::rename(&tmp, message_file(account_dir, id, MessageExt::Uid))
}

/// The mailbox UID counter (`.uidnext`), 0 when absent (no UID assigned yet).
pub(super) fn read_counter(account_dir: &Path) -> u32 {
	crate::util::fs_walk::read_to_string(state_file(account_dir, StateFile::UidNext))
		.ok()
		.and_then(|text| text.trim().parse().ok())
		.unwrap_or(0)
}

/// Persist the mailbox UID counter.
pub(super) fn write_counter(account_dir: &Path, value: u32) -> std::io::Result<()> {
	let tmp = state_tmp_file(account_dir, StateFile::UidNext);
	std::fs::write(&tmp, value.to_string())?;
	std::fs::rename(&tmp, state_file(account_dir, StateFile::UidNext))
}

/// The UID for `id`: its persisted value, or the next counter value (advancing
/// `counter` and persisting the assignment) when it has none yet.
pub(super) fn assign_or_read(account_dir: &Path, id: Uuid, counter: &mut u32) -> u32 {
	read_message(account_dir, id).unwrap_or_else(|| {
		*counter += 1;
		let _ = write_message(account_dir, id, *counter);
		*counter
	})
}
