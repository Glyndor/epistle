//! IMAP METADATA command handlers (RFC 5464). Server-level annotations use an
//! empty mailbox name; mailbox annotations require an existing mailbox.

use crate::imap::metadata;

use super::mailbox;
use super::{Output, Session};

impl Session {
	/// GETMETADATA: report the requested entries that have a stored value.
	pub(super) fn get_metadata(&self, tag: &str, mailbox: &str, entries: &[String]) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox.is_empty() && !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let mut pairs = String::new();
		for entry in entries {
			if let Some(value) = metadata::get(&self.data_dir, &account, mailbox, entry) {
				// Literal form carries arbitrary bytes safely.
				pairs.push_str(&format!(" \"{entry}\" {{{}}}\r\n{value}", value.len()));
			}
		}
		let untagged = if pairs.is_empty() {
			String::new()
		} else {
			format!("* METADATA \"{mailbox}\" ({})\r\n", pairs.trim_start())
		};
		Output::text(format!("{untagged}{tag} OK GETMETADATA completed\r\n"))
	}

	/// SETMETADATA: set or delete annotation entries.
	pub(super) fn set_metadata(
		&self,
		tag: &str,
		mailbox: &str,
		items: &[(String, Option<String>)],
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox.is_empty() && !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		for (entry, _) in items {
			if !metadata::valid_entry(entry) {
				return Output::text(format!("{tag} BAD invalid entry name\r\n"));
			}
		}
		for (entry, value) in items {
			if metadata::set(&self.data_dir, &account, mailbox, entry, value.as_deref()).is_err() {
				return Output::text(format!("{tag} NO SETMETADATA failed\r\n"));
			}
		}
		Output::text(format!("{tag} OK SETMETADATA completed\r\n"))
	}
}
