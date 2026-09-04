//! Tiny I/O helpers for `delivery.rs`: persist the IMAP `.flags` sidecar a
//! Sieve `addflag`/`setflag` produces, and the mailbox-name safety check.
//! Pulled out so the parent stays focused on the delivery decision tree.

use uuid::Uuid;

use crate::storage::spool::write_sync;

/// Persist Sieve-assigned flags as the message's IMAP `.flags` sidecar, so
/// a `setflag`/`addflag` filter is reflected when the mailbox is opened.
pub(super) fn write_flag_sidecar(new_dir: &std::path::Path, id: Uuid, flag_tokens: &[String]) {
	let flags: Vec<crate::imap::mailbox::Flag> = flag_tokens
		.iter()
		.filter_map(|token| crate::imap::mailbox::Flag::parse(token))
		.collect();
	if flags.is_empty() {
		return;
	}
	if let Ok(bytes) = serde_json::to_vec(&flags) {
		let _ = write_sync(&new_dir.join(format!("{id}.flags")), &bytes);
	}
}

/// A mailbox name safe to use as a single path segment.
pub(super) fn is_safe_mailbox(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= 64
		&& !name.starts_with('.')
		&& name
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
}