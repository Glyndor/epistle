//! IMAP METADATA command handlers (RFC 5464). Server-level annotations use an
//! empty mailbox name; mailbox annotations require an existing mailbox.

use crate::imap::metadata;
use crate::imap::session::commands::utf8::astring;

use super::super::mailbox;
use super::super::{Output, Session};

impl Session {
	/// GETMETADATA: report the requested entries that have a stored value.
	pub(in crate::imap::session) fn get_metadata(
		&self,
		tag: &str,
		mailbox: &str,
		entries: &[String],
	) -> Output {
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
				// The entry is quoted with `"` and `\` escaped: it came from a
				// quoted string that allowed both.
				pairs.push_str(&format!(
					" {} {{{}}}\r\n{value}",
					astring(entry, self.utf8_names()),
					value.len()
				));
			}
		}
		let untagged = if pairs.is_empty() {
			String::new()
		} else {
			format!(
				"* METADATA {} ({})\r\n",
				self.mailbox_astring(mailbox),
				pairs.trim_start()
			)
		};
		Output::text(format!("{untagged}{tag} OK GETMETADATA completed\r\n"))
	}

	/// SETMETADATA: set or delete annotation entries.
	pub(in crate::imap::session) fn set_metadata(
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
