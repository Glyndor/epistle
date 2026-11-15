//! IMAP ACL command handlers (RFC 4314). The authenticated account owns every
//! mailbox under it, so it always holds the full rights set; stored entries let
//! an operator pre-grant rights to other identifiers for future sharing.

use crate::imap::acl;

use super::super::mailbox;
use super::super::{Output, ResponseCode, Session, tagged_no};

enum AclMailboxError {
	NotAuthenticated,
	Missing,
	Denied,
}

impl Session {
	/// GETACL: report the owner's full rights plus any stored entries.
	pub(in crate::imap::session) fn get_acl(&self, tag: &str, mailbox: &str) -> Output {
		let account = match self.checked_mailbox(mailbox) {
			Ok(account) => account,
			Err(error) => return self.acl_error(tag, error),
		};
		let wire = self.mailbox_astring(mailbox);
		let mut line = format!("* ACL {wire} \"{account}\" {}", acl::ALL_RIGHTS);
		for (id, rights) in acl::get(&self.data_dir, &account, mailbox) {
			line.push_str(&format!(" \"{id}\" {rights}"));
		}
		Output::text(format!("{line}\r\n{tag} OK GETACL completed\r\n"))
	}

	/// MYRIGHTS: report the authenticated account's rights on the mailbox.
	pub(in crate::imap::session) fn my_rights(&self, tag: &str, mailbox: &str) -> Output {
		let account = match self.checked_mailbox(mailbox) {
			Ok(account) => account,
			Err(error) => return self.acl_error(tag, error),
		};
		let rights = acl::rights_of(&self.data_dir, &account, mailbox, &account);
		Output::text(format!(
			"* MYRIGHTS {} {rights}\r\n{tag} OK MYRIGHTS completed\r\n",
			self.mailbox_astring(mailbox)
		))
	}

	/// LISTRIGHTS: the rights guaranteed to, and grantable for, an identifier.
	pub(in crate::imap::session) fn list_rights(
		&self,
		tag: &str,
		mailbox: &str,
		identifier: &str,
	) -> Output {
		let account = match self.checked_mailbox(mailbox) {
			Ok(account) => account,
			Err(error) => return self.acl_error(tag, error),
		};
		// The owner always has all rights; others may be granted any right.
		let body = if identifier == account {
			acl::ALL_RIGHTS.to_string()
		} else {
			let optional: Vec<String> = acl::ALL_RIGHTS.chars().map(|c| c.to_string()).collect();
			format!("\"\" {}", optional.join(" "))
		};
		Output::text(format!(
			"* LISTRIGHTS {} \"{identifier}\" {body}\r\n{tag} OK LISTRIGHTS completed\r\n",
			self.mailbox_astring(mailbox)
		))
	}

	/// SETACL: grant/modify rights for an identifier on a mailbox.
	pub(in crate::imap::session) fn set_acl(
		&self,
		tag: &str,
		mailbox: &str,
		identifier: &str,
		rights: &str,
	) -> Output {
		let account = match self.checked_mailbox(mailbox) {
			Ok(account) => account,
			Err(error) => return self.acl_error(tag, error),
		};
		let body = rights.strip_prefix(['+', '-']).unwrap_or(rights);
		if !acl::valid_rights(body) {
			return Output::text(format!("{tag} BAD [CLIENTBUG] invalid rights\r\n"));
		}
		match acl::set(&self.data_dir, &account, mailbox, identifier, rights) {
			Ok(_) => Output::text(format!("{tag} OK SETACL completed\r\n")),
			Err(_) => Output::text(format!("{tag} NO [SERVERBUG] SETACL failed\r\n")),
		}
	}

	/// DELETEACL: remove an identifier's rights on a mailbox.
	pub(in crate::imap::session) fn delete_acl(
		&self,
		tag: &str,
		mailbox: &str,
		identifier: &str,
	) -> Output {
		let account = match self.checked_mailbox(mailbox) {
			Ok(account) => account,
			Err(error) => return self.acl_error(tag, error),
		};
		match acl::delete(&self.data_dir, &account, mailbox, identifier) {
			Ok(()) => Output::text(format!("{tag} OK DELETEACL completed\r\n")),
			Err(_) => Output::text(format!("{tag} NO [SERVERBUG] DELETEACL failed\r\n")),
		}
	}

	/// The account when the session may access the mailbox.
	fn checked_mailbox(&self, mailbox: &str) -> Result<String, AclMailboxError> {
		let Some(account) = self.account().map(str::to_string) else {
			return Err(AclMailboxError::NotAuthenticated);
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Err(AclMailboxError::Missing);
		}
		if !acl::rights_of(&self.data_dir, &account, mailbox, &account).contains('l') {
			return Err(AclMailboxError::Denied);
		}
		Ok(account)
	}

	/// The error reply for an ACL command refused by state, existence or rights.
	fn acl_error(&self, tag: &str, error: AclMailboxError) -> Output {
		match error {
			AclMailboxError::NotAuthenticated => {
				Output::text(format!("{tag} BAD not authenticated\r\n"))
			}
			AclMailboxError::Missing => {
				Output::text(format!("{tag} NO [NONEXISTENT] no such mailbox\r\n"))
			}
			AclMailboxError::Denied => tagged_no(tag, ResponseCode::NoPerm, "access denied"),
		}
	}
}
