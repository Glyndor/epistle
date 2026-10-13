//! Tiny I/O helpers for `delivery.rs`: persist the IMAP `.flags` sidecar a
//! Sieve `addflag`/`setflag` produces, the mailbox-name safety check, and
//! the stored spelling of a Sieve `fileinto` target.
//! Pulled out so the parent stays focused on the delivery decision tree.

use uuid::Uuid;

use crate::storage::spool::write_sync;
use crate::util::path_component::AccountName;

/// Persist Sieve-assigned flags as the message's IMAP `.flags` sidecar, so
/// a `setflag`/`addflag` filter is reflected when the mailbox is opened.
pub(super) fn write_flag_sidecar(new_dir: &std::path::Path, id: Uuid, flag_tokens: &[String]) {
	use crate::util::path_component::{MessageExt, message_file};
	let flags: Vec<crate::imap::mailbox::Flag> = flag_tokens
		.iter()
		.filter_map(|token| crate::imap::mailbox::Flag::parse(token))
		.collect();
	if flags.is_empty() {
		return;
	}
	if let Ok(bytes) = serde_json::to_vec(&flags)
		&& let Ok(path) = message_file(new_dir, id, MessageExt::Flags)
	{
		let _ = write_sync(&path, &bytes);
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

/// The stored spelling of a mailbox a Sieve script names. Sieve names are
/// UTF-8 (RFC 5228) and folders are stored under their modified
/// UTF-7 encoding, so `fileinto "Año"` reaches the folder an IMAP `CREATE`
/// of the same name made (`A&APE-o`). `None` when IMAP would refuse the
/// name too, such as one holding the `/` delimiter of a hierarchy this
/// flat store does not have.
pub(super) fn sieve_mailbox(name: &str) -> Option<String> {
	use crate::util::path_component::MailboxName;
	let stored = crate::util::mutf7::encode(name);
	match MailboxName::new(&stored).ok()? {
		MailboxName::Inbox => Some("INBOX".to_string()),
		MailboxName::Folder(_) => Some(stored),
	}
}

/// Whether the named mailbox already exists in the account (INBOX is
/// always present for a valid account).
pub(super) fn mailbox_exists(data_dir: &std::path::Path, account: &str, mailbox: &str) -> bool {
	if mailbox.eq_ignore_ascii_case("INBOX") {
		return AccountName::new(account).is_ok();
	}
	crate::imap::mailbox::exists(data_dir, account, mailbox)
}

/// Create the named mailbox if it does not exist (RFC 5490 §3.2 `:create`).
/// Errors from `imap::mailbox::create` are swallowed: a failed create
/// turns the fileinto into a run-time error that the delivery path
/// falls back from, never a delivery failure that loses mail.
pub(super) fn ensure_mailbox(data_dir: &std::path::Path, account: &str, mailbox: &str) {
	let _ = crate::imap::mailbox::create(data_dir, account, mailbox);
}
