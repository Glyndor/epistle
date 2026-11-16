//! The RFC 6154 special-use role of a mailbox.
//!
//! The role comes from what the account itself recorded ([`roles`]) and, for
//! a role it recorded nothing for, from the well-known name the server and
//! the account agree on; never from anything a client says about a message.
//! The same answer serves LIST and the decision to learn from a move.

use crate::util::mailbox_path::canonical;

mod policy;
pub mod roles;

pub use policy::FolderPolicy;
pub use roles::{Role, Roles};

/// The special-use attribute for a well-known mailbox name, or an empty
/// string. Matching is case-insensitive on the whole name, so a folder
/// called `Junk` under `Archive` has no role.
pub fn attribute(name: &str) -> &'static str {
	match name.to_ascii_lowercase().as_str() {
		"junk" | "spam" | "rejects" => "\\Junk",
		"drafts" => "\\Drafts",
		"sent" => "\\Sent",
		"trash" | "deleted" => "\\Trash",
		"archive" => "\\Archive",
		_ => "",
	}
}

/// The mailbox that holds the copy of the mail `account` sends: the one the
/// account recorded for the `\Sent` role while it exists, else `Sent`.
pub fn sent_folder(data_dir: &std::path::Path, account: &str) -> String {
	Roles::load(data_dir, account).folder(data_dir, account, Role::Sent, "Sent")
}

/// Whether `name` is the account's Junk mailbox.
pub fn is_junk(name: &str) -> bool {
	attribute(&canonical(name)) == "\\Junk"
}

/// Whether `name` is the account's Trash mailbox.
pub fn is_trash(name: &str) -> bool {
	attribute(&canonical(name)) == "\\Trash"
}

#[cfg(test)]
mod tests;
