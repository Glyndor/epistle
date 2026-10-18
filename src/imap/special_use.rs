//! The RFC 6154 special-use role of a well-known mailbox name.
//!
//! The role comes from the name the server and the account agree on, never
//! from anything a client says about a message. The same table answers LIST
//! and the decision to learn from a move.

use crate::util::mailbox_path::canonical;

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

/// Whether `name` is the account's Junk mailbox.
pub fn is_junk(name: &str) -> bool {
	attribute(&canonical(name)) == "\\Junk"
}

/// Whether `name` is the account's Trash mailbox.
pub fn is_trash(name: &str) -> bool {
	attribute(&canonical(name)) == "\\Trash"
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn roles_follow_the_whole_name() {
		assert!(is_junk("Junk") && is_junk("rejects") && is_junk("SPAM"));
		assert!(is_trash("Trash") && is_trash("deleted"));
		assert!(!is_junk("Archive/Junk"), "a nested folder has no role");
		assert!(!is_junk("INBOX") && !is_trash("Junk"));
	}
}
