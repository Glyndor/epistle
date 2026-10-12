//! Glue between mailbox operations and the account's JMAP change journal
//! ([`crate::imap::changelog`]).

use std::path::Path;

use uuid::Uuid;

use crate::imap::changelog::{self, Change};
use crate::util::path_component::AccountName;

/// Record `changes` for `account`, best-effort.
pub(crate) fn note(data_dir: &Path, account: &AccountName<'_>, changes: &[Change]) {
	if let Ok(root) = account.root(data_dir) {
		changelog::note(root.as_path(), changes);
	}
}

/// The ids of the messages in a mailbox's `new/` directory.
pub(crate) fn message_ids(messages_dir: &Path) -> Vec<Uuid> {
	let Ok(entries) = crate::util::fs_walk::read_dir(messages_dir) else {
		return Vec::new();
	};
	entries
		.flatten()
		.filter_map(|entry| {
			let name = entry.file_name();
			Uuid::parse_str(name.to_str()?.strip_suffix(".eml")?).ok()
		})
		.collect()
}
