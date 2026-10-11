//! Mod-sequence sidecar storage for CONDSTORE (RFC 7162).
//!
//! Each message carries its last-change mod-sequence in `<id>.modseq`; the
//! mailbox's monotonic counter lives in `.modseqctr`.

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
pub(super) fn next_counter(account_dir: &Path) -> std::io::Result<u64> {
	let next = read_counter(account_dir) + 1;
	let tmp = state_tmp_file(account_dir, StateFile::ModseqCounter)?;
	std::fs::write(&tmp, next.to_string())?;
	std::fs::rename(&tmp, state_file(account_dir, StateFile::ModseqCounter)?)?;
	Ok(next)
}
