//! Mailbox scan: the authoritative slow path for [`super::mailbox::Snapshot::open_at`].
//!
//! Reads every `.eml` file in the mailbox directory, the matching `.flags`
//! and `.modseq` sidecars, assigns UIDs in UUID-sorted order and returns the messages sorted by UID. The
//! assignment is serialised with the mailbox's UID lock, so two scans of one
//! mailbox never hand the same UID to two messages; a scan that finds every
//! UID already assigned takes no lock at all.

use std::path::Path;

use uuid::Uuid;

use crate::imap::mailbox::MessageRef;
use crate::storage::MessageCrypto;
use crate::util::path_component::{MessageExt, message_file};

/// Scan `account_dir` and build a `Vec<MessageRef>` sorted by UID (UUID order until a message with a lower
/// UUID than the others arrives).
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
	match crate::util::fs_walk::read_dir(account_dir) {
		Ok(entries) => {
			for entry in entries {
				let entry = entry?;
				if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
					continue;
				}
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
	// The UIDs of every message, the missing ones assigned under the
	// mailbox's UID lock.
	let uids = super::uid::resolve_uids(account_dir, &ids);
	// A sequence number must grow with the UID (RFC 9051 §2.3.1.1), and the
	// client numbers a message that arrived while it was away after the ones
	// it knew. A message whose UUID sorts before the others (the clock went
	// back, or an old file was copied in) takes the highest UID, so the
	// mailbox is ordered by UID, not by file name.
	let mut order: Vec<(u32, Uuid)> = uids.into_iter().zip(ids.iter().copied()).collect();
	order.sort();
	let mut messages = Vec::with_capacity(ids.len());
	for (uid, id) in order {
		let path = message_file(account_dir, id, MessageExt::Eml)?;
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
			uid,
			id,
			size,
			flags: super::flags::read_flags(account_dir, id),
			internal_date,
			internal_zone: super::internal_date::read_zone(account_dir, id),
			modseq: super::modseq::read_message(account_dir, id),
		});
	}
	Ok(messages)
}
