//! Mailbox scan: the authoritative slow path for [`super::mailbox::Snapshot::open_at`].
//!
//! Reads every `.eml` file in the mailbox directory, the matching `.flags`
//! and `.modseq` sidecars, and assigns UIDs in UUID-sorted order. Also
//! persists a fresh `.uid` counter when the scan observed a UID it did not
//! know about.

use std::path::Path;

use uuid::Uuid;

use crate::imap::mailbox::MessageRef;
use crate::storage::MessageCrypto;

/// Scan `account_dir` and build a `Vec<MessageRef>` in UUID-sorted order.
///
/// Pulled out of [`super::mailbox`] so the open path can stay compact. The
/// open path still owns the surrounding `Snapshot` plumbing (uid_validity,
/// highest_modseq, index write-back, archive fields) — this helper returns
/// only the per-message state.
pub(super) fn scan_mailbox(
	account_dir: &Path,
	crypto: &MessageCrypto,
) -> std::io::Result<Vec<MessageRef>> {
	let mut ids: Vec<Uuid> = Vec::new();
	match std::fs::read_dir(account_dir) {
		Ok(entries) => {
			for entry in entries {
				let entry = entry?;
				let name = entry.file_name();
				let Some(name) = name.to_str() else { continue };
				if let Some(stem) = name.strip_suffix(".eml")
					&& let Ok(id) = Uuid::parse_str(stem)
				{
					ids.push(id);
				}
			}
		}
		// An account that never received mail has no directory yet.
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
		Err(error) => return Err(error),
	}
	ids.sort();
	let initial_counter = super::uid::read_counter(account_dir);
	let mut uid_counter = initial_counter;
	let mut messages = Vec::with_capacity(ids.len());
	for id in &ids {
		let path = account_dir.join(format!("{id}.eml"));
		let meta = std::fs::metadata(&path);
		// RFC822.SIZE must be the plaintext size a client sees, not the
		// on-disk envelope size, so subtract the fixed crypto overhead for an
		// encrypted file.
		let size = meta
			.as_ref()
			.map(|m| crypto.stored_plaintext_len(&path, m.len()))
			.unwrap_or(0);
		let internal_date = meta
			.as_ref()
			.ok()
			.and_then(|m| m.modified().ok())
			.unwrap_or(std::time::SystemTime::UNIX_EPOCH);
		messages.push(MessageRef {
			uid: super::uid::assign_or_read(account_dir, *id, &mut uid_counter),
			id: *id,
			size,
			flags: super::flags::read_flags(account_dir, *id),
			internal_date,
			modseq: super::modseq::read_message(account_dir, *id),
		});
	}
	if uid_counter > initial_counter {
		let _ = super::uid::write_counter(account_dir, uid_counter);
	}
	Ok(messages)
}
