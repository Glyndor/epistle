//! IMAP LIST / STATUS (RFC 9051 §6.3, RFC 5819).

use std::collections::HashSet;

use super::super::command::{ListAttribute, StatusItem};
use super::{Output, Session, helpers, mailbox};

impl Session {
	pub(super) fn list(
		&mut self,
		tag: &str,
		pattern: &str,
		return_status: &[StatusItem],
		select_subscribed: bool,
		return_attributes: &[ListAttribute],
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let subscribed: HashSet<String> = mailbox::list_subscribed(&self.data_dir, &account)
			.into_iter()
			.collect();
		let mut response = String::new();
		for name in mailbox::list(&self.data_dir, &account) {
			let matches = pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case(&name);
			// LIST-EXTENDED (RFC 5258): `(SUBSCRIBED)` lists only subscribed boxes.
			if !matches || (select_subscribed && !subscribed.contains(&name)) {
				continue;
			}
			let mut attributes =
				if self.imap4rev2 || return_attributes.contains(&ListAttribute::SpecialUse) {
					helpers::special_use_attribute(&name).to_string()
				} else {
					String::new()
				};
			if subscribed.contains(&name)
				&& (self.imap4rev2 || return_attributes.contains(&ListAttribute::Subscribed))
			{
				if !attributes.is_empty() {
					attributes.push(' ');
				}
				attributes.push_str("\\Subscribed");
			}
			// The store is flat, so an explicitly requested child state is a leaf.
			if self.imap4rev2 || return_attributes.contains(&ListAttribute::Children) {
				if !attributes.is_empty() {
					attributes.push(' ');
				}
				attributes.push_str("\\HasNoChildren");
			}
			response.push_str(&format!("* LIST ({attributes}) \"/\" \"{name}\"\r\n"));
			// LIST-STATUS (RFC 5819): report the requested STATUS inline.
			if !return_status.is_empty()
				&& let Some(parts) = self.status_parts(&account, &name, return_status)
			{
				response.push_str(&format!("* STATUS \"{name}\" ({parts})\r\n"));
			}
		}
		response.push_str(&format!("{tag} OK LIST completed\r\n"));
		Output::text(response)
	}

	pub(super) fn status(&mut self, tag: &str, mailbox: &str, items: &[StatusItem]) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let Some(parts) = self.status_parts(&account, mailbox, items) else {
			return Output::text(format!("{tag} NO cannot open mailbox\r\n"));
		};
		Output::text(format!(
			"* STATUS \"{mailbox}\" ({parts})\r\n{tag} OK STATUS completed\r\n"
		))
	}

	/// The `ITEM value ...` body of a STATUS response, or `None` if the mailbox
	/// cannot be opened. Shared by STATUS and LIST ... RETURN (STATUS ...).
	pub(super) fn status_parts(
		&self,
		account: &str,
		mailbox_name: &str,
		items: &[StatusItem],
	) -> Option<String> {
		let snapshot = self.open_snapshot(account, mailbox_name).ok()?;
		let count_flag = |flag: mailbox::Flag| {
			snapshot
				.messages()
				.filter(|m| m.flags.contains(&flag))
				.count()
		};
		let mut parts = String::new();
		for (i, item) in items.iter().enumerate() {
			if i > 0 {
				parts.push(' ');
			}
			let rendered = match item {
				StatusItem::Messages => format!("MESSAGES {}", snapshot.len()),
				StatusItem::Recent => "RECENT 0".to_string(),
				StatusItem::Uidnext => format!("UIDNEXT {}", snapshot.uid_next()),
				StatusItem::Uidvalidity => format!("UIDVALIDITY {}", snapshot.uid_validity()),
				StatusItem::Unseen => {
					format!(
						"UNSEEN {}",
						snapshot.len() - count_flag(mailbox::Flag::Seen)
					)
				}
				StatusItem::Size => {
					format!("SIZE {}", snapshot.messages().map(|m| m.size).sum::<u64>())
				}
				StatusItem::Deleted => {
					format!("DELETED {}", count_flag(mailbox::Flag::Deleted))
				}
				StatusItem::MailboxId => {
					format!("MAILBOXID (M{})", snapshot.uid_validity())
				}
			};
			parts.push_str(&rendered);
		}
		Some(parts)
	}
}
