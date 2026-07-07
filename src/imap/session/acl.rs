//! IMAP ACL command handlers (RFC 4314). The authenticated account owns every
//! mailbox under it, so it always holds the full rights set; stored entries let
//! an operator pre-grant rights to other identifiers for future sharing.

use crate::imap::acl;

use super::mailbox;
use super::{Output, Session};

impl Session {
	/// GETACL: report the owner's full rights plus any stored entries.
	pub(super) fn get_acl(&self, tag: &str, mailbox: &str) -> Output {
		let Some(account) = self.checked_mailbox(mailbox) else {
			return self.acl_error(tag);
		};
		let mut line = format!("* ACL \"{mailbox}\" \"{account}\" {}", acl::ALL_RIGHTS);
		for (id, rights) in acl::get(&self.data_dir, &account, mailbox) {
			line.push_str(&format!(" \"{id}\" {rights}"));
		}
		Output::text(format!("{line}\r\n{tag} OK GETACL completed\r\n"))
	}

	/// MYRIGHTS: report the authenticated account's rights on the mailbox.
	pub(super) fn my_rights(&self, tag: &str, mailbox: &str) -> Output {
		let Some(account) = self.checked_mailbox(mailbox) else {
			return self.acl_error(tag);
		};
		let rights = acl::rights_of(&self.data_dir, &account, mailbox, &account);
		Output::text(format!(
			"* MYRIGHTS \"{mailbox}\" {rights}\r\n{tag} OK MYRIGHTS completed\r\n"
		))
	}

	/// LISTRIGHTS: the rights guaranteed to, and grantable for, an identifier.
	pub(super) fn list_rights(&self, tag: &str, mailbox: &str, identifier: &str) -> Output {
		let Some(account) = self.checked_mailbox(mailbox) else {
			return self.acl_error(tag);
		};
		// The owner always has all rights; others may be granted any right.
		let body = if identifier == account {
			acl::ALL_RIGHTS.to_string()
		} else {
			let optional: Vec<String> = acl::ALL_RIGHTS.chars().map(|c| c.to_string()).collect();
			format!("\"\" {}", optional.join(" "))
		};
		Output::text(format!(
			"* LISTRIGHTS \"{mailbox}\" \"{identifier}\" {body}\r\n{tag} OK LISTRIGHTS completed\r\n"
		))
	}

	/// SETACL: grant/modify rights for an identifier on a mailbox.
	pub(super) fn set_acl(
		&self,
		tag: &str,
		mailbox: &str,
		identifier: &str,
		rights: &str,
	) -> Output {
		let Some(account) = self.checked_mailbox(mailbox) else {
			return self.acl_error(tag);
		};
		let body = rights.strip_prefix(['+', '-']).unwrap_or(rights);
		if !acl::valid_rights(body) {
			return Output::text(format!("{tag} BAD invalid rights\r\n"));
		}
		match acl::set(&self.data_dir, &account, mailbox, identifier, rights) {
			Ok(_) => Output::text(format!("{tag} OK SETACL completed\r\n")),
			Err(_) => Output::text(format!("{tag} NO SETACL failed\r\n")),
		}
	}

	/// DELETEACL: remove an identifier's rights on a mailbox.
	pub(super) fn delete_acl(&self, tag: &str, mailbox: &str, identifier: &str) -> Output {
		let Some(account) = self.checked_mailbox(mailbox) else {
			return self.acl_error(tag);
		};
		match acl::delete(&self.data_dir, &account, mailbox, identifier) {
			Ok(()) => Output::text(format!("{tag} OK DELETEACL completed\r\n")),
			Err(_) => Output::text(format!("{tag} NO DELETEACL failed\r\n")),
		}
	}

	/// The account if authenticated and the mailbox exists; otherwise `None`.
	fn checked_mailbox(&self, mailbox: &str) -> Option<String> {
		let account = self.account()?.to_string();
		mailbox::exists(&self.data_dir, &account, mailbox).then_some(account)
	}

	/// The error reply for an ACL command on a missing mailbox or session.
	fn acl_error(&self, tag: &str) -> Output {
		if self.account().is_none() {
			Output::text(format!("{tag} NO not authenticated\r\n"))
		} else {
			Output::text(format!("{tag} NO no such mailbox\r\n"))
		}
	}
}
