//! Mod-sequence sidecar storage for CONDSTORE (RFC 7162).
//!
//! Each message carries its last-change mod-sequence in `<id>.modseq`; the
//! mailbox's monotonic counter lives in `.modseqctr`. The counter is shared by
//! every session that stores a flag in the mailbox, so it advances under an
//! advisory lock on `.modseq_lock`: two STOREs at the same time must never
//! hand out the same mod-sequence.

use std::path::Path;

use crate::util::path_component::{
	MessageExt, StateFile, message_file, message_tmp_file, state_file, state_tmp_file,
};
use uuid::Uuid;

/// A message's stored mod-sequence, or 1 when none has been recorded.
pub(super) fn read_message(account_dir: &Path, id: Uuid) -> u64 {
	message_file(account_dir, id, MessageExt::Modseq)
		.and_then(crate::util::fs_walk::read_to_string)
		.ok()
		.and_then(|s| s.trim().parse().ok())
		.unwrap_or(1)
}

/// Stamp a message with `modseq`, crash-safely.
pub(super) fn write_message(account_dir: &Path, id: Uuid, modseq: u64) -> std::io::Result<()> {
	let tmp = message_tmp_file(account_dir, id, MessageExt::Modseq)?;
	std::fs::write(&tmp, modseq.to_string())?;
	std::fs::rename(&tmp, message_file(account_dir, id, MessageExt::Modseq)?)
}

/// The mailbox mod-sequence counter (`.modseqctr`), 1 when absent.
pub(super) fn read_counter(account_dir: &Path) -> u64 {
	state_file(account_dir, StateFile::ModseqCounter)
		.and_then(crate::util::fs_walk::read_to_string)
		.ok()
		.and_then(|s| s.trim().parse().ok())
		.unwrap_or(1)
}

/// Advance and persist the mailbox counter, returning the new value.
///
/// The read, the increment and the write run under the mailbox's mod-sequence
/// lock. Two STOREs of one mailbox at the same time would otherwise read the
/// same counter and hand out the same mod-sequence — RFC 7162 wants strictly
/// increasing values — and the second rename would fail with ENOENT, so the
/// client would be told the flags could not be stored although they were.
pub(super) fn next_counter(account_dir: &Path) -> std::io::Result<u64> {
	// The guard is held until the end of the function: the counter must not
	// advance between the read and the write.
	let _guard = match lock(account_dir) {
		Ok(file) => Some(file),
		Err(error) => {
			// The lock cannot be taken: the counter advances without it, as it
			// did before, and two stores of this mailbox can race.
			tracing::warn!(
				%error,
				mailbox = %crate::log_id::path(account_dir),
				"could not take the mailbox mod-sequence lock; advancing the counter without it"
			);
			None
		}
	};
	let next = read_counter(account_dir) + 1;
	let tmp = state_tmp_file(account_dir, StateFile::ModseqCounter)?;
	std::fs::write(&tmp, next.to_string())?;
	std::fs::rename(&tmp, state_file(account_dir, StateFile::ModseqCounter)?)?;
	Ok(next)
}

/// Take the mailbox's mod-sequence lock: an exclusive advisory lock on
/// `.modseq_lock`, released when the returned file is dropped.
///
/// The name cannot be a message file: a message's files are `<id><ext>`, and
/// this one starts with a dot.
pub(super) fn lock(account_dir: &Path) -> std::io::Result<std::fs::File> {
	let file = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.open(state_file(account_dir, StateFile::ModseqLock)?)?;
	file.lock()?;
	Ok(file)
}

#[cfg(test)]
mod tests;
