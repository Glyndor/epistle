//! The special-use role of a mailbox as the account itself records it.
//!
//! The role of a folder used to come from its English name alone, so a
//! folder that was renamed or created in another language lost it. An
//! account now keeps its own map from role to mailbox name, in
//! `<account>/.roles`, and that map wins: a role that has an entry belongs
//! to the folder the entry names, and the name table of
//! [`super::attribute`] only answers for the roles the account has no entry
//! for. An account with no file behaves exactly as before.

mod store;

use std::collections::BTreeMap;
use std::path::Path;

pub use store::{clear, forget, moved, set};

/// A role an account assigns to one of its mailboxes (RFC 6154).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
	/// Spam. Every filter that quarantines mail delivers here.
	Junk,
	/// Deleted mail.
	Trash,
	/// The copy of sent mail.
	Sent,
	/// Messages being written.
	Drafts,
	/// Mail kept out of the inbox.
	Archive,
}

impl Role {
	/// Every role, in the order folders are created.
	pub const ALL: [Role; 5] = [
		Role::Junk,
		Role::Sent,
		Role::Drafts,
		Role::Trash,
		Role::Archive,
	];

	/// The RFC 6154 attribute.
	pub fn attribute(self) -> &'static str {
		match self {
			Role::Junk => "\\Junk",
			Role::Trash => "\\Trash",
			Role::Sent => "\\Sent",
			Role::Drafts => "\\Drafts",
			Role::Archive => "\\Archive",
		}
	}

	/// The lower case word the file, the CLI and the configuration use.
	pub fn key(self) -> &'static str {
		match self {
			Role::Junk => "junk",
			Role::Trash => "trash",
			Role::Sent => "sent",
			Role::Drafts => "drafts",
			Role::Archive => "archive",
		}
	}

	/// The role a key (`junk`) or an attribute (`\Junk`) names.
	pub fn parse(text: &str) -> Option<Role> {
		let text = text.trim().trim_start_matches('\\');
		Role::ALL
			.into_iter()
			.find(|role| role.key().eq_ignore_ascii_case(text))
	}

	/// The role the fixed English name table gives `name`, if any.
	pub fn of_name(name: &str) -> Option<Role> {
		let attribute = super::attribute(name);
		Role::ALL
			.into_iter()
			.find(|role| role.attribute() == attribute)
	}
}

/// What one account has recorded: role to mailbox name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roles {
	map: BTreeMap<Role, String>,
}

impl Roles {
	/// The roles recorded for `account`. A missing, unreadable or malformed
	/// file records nothing, which is the behaviour of an account that never
	/// had one.
	pub fn load(data_dir: &Path, account: &str) -> Roles {
		Roles {
			map: store::read(data_dir, account),
		}
	}

	/// The mailbox recorded for `role`, whether or not it still exists.
	pub fn recorded(&self, role: Role) -> Option<&str> {
		self.map.get(&role).map(String::as_str)
	}

	/// Every recorded role with its mailbox.
	pub fn iter(&self) -> impl Iterator<Item = (Role, &str)> {
		self.map.iter().map(|(role, name)| (*role, name.as_str()))
	}

	/// The role of `name`: the one recorded for it, else the one its name
	/// gives, unless the account recorded that role for another folder.
	pub fn role_of(&self, name: &str) -> Option<Role> {
		if let Some((role, _)) = self
			.map
			.iter()
			.find(|(_, recorded)| recorded.eq_ignore_ascii_case(name))
		{
			return Some(*role);
		}
		Role::of_name(name).filter(|role| !self.map.contains_key(role))
	}

	/// The RFC 6154 attribute of `name`, or an empty string.
	pub fn attribute(&self, name: &str) -> &'static str {
		self.role_of(name).map_or("", Role::attribute)
	}

	/// Whether `name` is the account's Junk mailbox.
	pub fn is_junk(&self, name: &str) -> bool {
		self.role_of(&crate::util::mailbox_path::canonical(name)) == Some(Role::Junk)
	}

	/// Whether `name` is the account's Trash mailbox.
	pub fn is_trash(&self, name: &str) -> bool {
		self.role_of(&crate::util::mailbox_path::canonical(name)) == Some(Role::Trash)
	}

	/// The mailbox holding `role` when the account recorded one that still
	/// exists, else `default`. A role whose folder was deleted behind the
	/// account's back must not bring it back by the next delivery.
	pub fn folder(&self, data_dir: &Path, account: &str, role: Role, default: &str) -> String {
		match self.recorded(role) {
			Some(name) if crate::imap::mailbox::exists(data_dir, account, name) => name.to_string(),
			_ => default.to_string(),
		}
	}
}

#[cfg(test)]
mod tests;
