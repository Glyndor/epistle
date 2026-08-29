//! Per-message flag sidecar: read, write, and equality on the `Vec<Flag>`
//! stored at `<id>.flags` (RFC 9051 §2.3.2 as a JSON array of canonical
//! tokens).
//!
//! The two helpers are used by the mailbox snapshot open/scan path (to load
//! each message's flag set on the slow path) and by the snapshot STORE
//! path (to persist a no-op-skipping flag change). The equality test
//! catches the common "re-mark \Seen" pattern that would otherwise re-write
//! the sidecar and bump the mod-sequence.

use std::path::Path;

use uuid::Uuid;

use crate::imap::mailbox::Flag;

/// Read the `.flags` sidecar for `id` and decode it as a JSON array. A
/// missing or unparseable file is treated as no flags set; a present but
/// malformed sidecar is also treated as empty rather than crashing the
/// snapshot open.
pub(super) fn read_flags(account_dir: &Path, id: Uuid) -> Vec<Flag> {
	std::fs::read(account_dir.join(format!("{id}.flags")))
		.ok()
		.and_then(|bytes| serde_json::from_slice(&bytes).ok())
		.unwrap_or_default()
}

/// Write `flags` as a JSON array to a `<id>.flags` sidecar, atomically
/// (temp file + rename).
pub(super) fn write_flags(account_dir: &Path, id: Uuid, flags: &[Flag]) -> std::io::Result<()> {
	let bytes = serde_json::to_vec(flags).map_err(std::io::Error::other)?;
	let tmp = account_dir.join(format!("{id}.flags.tmp"));
	std::fs::write(&tmp, &bytes)?;
	std::fs::rename(&tmp, account_dir.join(format!("{id}.flags")))
}

/// Whether two flag lists denote the same flag set, independent of order or
/// duplicates. Used to detect a no-op STORE and avoid a redundant disk write.
pub(super) fn flags_equal(current: &[Flag], next: &[Flag]) -> bool {
	current.iter().all(|flag| next.contains(flag)) && next.iter().all(|flag| current.contains(flag))
}
