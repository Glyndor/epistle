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

/// The most folders an account may hold before a Sieve `fileinto` stops
/// creating new ones (INBOX counts). A script that files by something a
/// sender chooses, such as `fileinto "${1}"` on the Subject, would otherwise
/// make one for every message; past this the message is kept in INBOX.
pub(super) const MAX_AUTO_FOLDERS: usize = 200;

/// A mailbox name a routing rule may target: levels of ASCII letters,
/// digits, `-`, `_` and space, separated by the `/` hierarchy delimiter, at
/// most 64 bytes in all. Each level is a valid folder level, so the name maps
/// to one directory under `folders/` like any other mailbox.
pub(super) fn is_safe_mailbox(name: &str) -> bool {
	name.len() <= 64
		&& name.split('/').all(|level| {
			!level.is_empty()
				&& level
					.chars()
					.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
		})
}

/// The stored spelling of a mailbox a Sieve script names. Sieve names are
/// UTF-8 (RFC 5228) and folders are stored under their modified
/// UTF-7 encoding, so `fileinto "Año"` reaches the folder an IMAP `CREATE`
/// of the same name made (`A&APE-o`), and `fileinto "Lists/Rust"` reaches
/// the subfolder `Rust` of `Lists`. `None` when IMAP would refuse the name
/// too, such as one with an empty level (`Lists//Rust`).
pub(super) fn sieve_mailbox(name: &str) -> Option<String> {
	use crate::util::path_component::MailboxName;
	// The name is what a script built, perhaps from a header a sender wrote:
	// not longer than a person would name a folder, and nothing that changes
	// the direction text is shown in.
	if name.chars().count() > MAX_FOLDER_NAME_CHARS || name.chars().any(is_bidi_control) {
		return None;
	}
	let stored = crate::util::mutf7::encode(name);
	match MailboxName::new(&stored).ok()? {
		MailboxName::Inbox => Some("INBOX".to_string()),
		MailboxName::Folder(_) => Some(stored),
	}
}

/// The longest folder name, in characters, a Sieve `fileinto` may use.
const MAX_FOLDER_NAME_CHARS: usize = 128;

/// The characters that reorder or isolate the text around them (Unicode
/// bidirectional formatting): in a folder name they make one look like
/// another.
fn is_bidi_control(c: char) -> bool {
	matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Whether a new folder may be made in the account: it holds fewer than
/// [`MAX_AUTO_FOLDERS`] (INBOX included).
pub(super) fn may_create_mailbox(data_dir: &std::path::Path, account: &str) -> bool {
	crate::imap::mailbox::list(data_dir, account).len() < MAX_AUTO_FOLDERS
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
