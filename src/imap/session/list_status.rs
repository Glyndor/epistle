//! IMAP LIST / STATUS (RFC 9051 §6.3, RFC 5819).

use std::collections::HashSet;

use super::super::command::{ListAttribute, ListCommand, StatusItem};
use super::{Output, Session, helpers, mailbox};
use crate::imap::list_pattern;
use crate::imap::list_tree::{self, Entry, Hidden};

/// The `CHILDINFO` extended data (RFC 5258 §3.5): the selection options a
/// hidden descendant meets.
fn child_info(request: &ListCommand) -> String {
	let mut options = Vec::new();
	if request.select_subscribed {
		options.push("\"SUBSCRIBED\"");
	}
	if request.select_special_use {
		options.push("\"SPECIAL-USE\"");
	}
	format!(" (\"CHILDINFO\" ({}))", options.join(" "))
}

impl Session {
	pub(super) fn list(&mut self, tag: &str, request: &ListCommand) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let subscriptions = mailbox::list_subscribed(&self.data_dir, &account);
		let subscribed: HashSet<&str> = subscriptions.iter().map(String::as_str).collect();
		let mut response = String::new();
		// RFC 3501 §6.3.8: `LIST "" ""` is the canonical hierarchy-
		// separator discovery call. The reply is a `LIST` line for
		// the root of the hierarchy with `\Noselect` (the root is
		// never selectable itself) and the delimiter the regular
		// mailboxes use. Skipped when the caller restricted the
		// listing with `SUBSCRIBED` or `SPECIAL-USE`, both of which
		// the root never has, so emitting it would be a misleading
		// match for clients that treat the absence of `\Subscribed`
		// as "nothing here".
		if request.patterns.iter().all(String::is_empty)
			&& !request.select_subscribed
			&& !request.select_special_use
		{
			response.push_str("* LIST (\\Noselect) \"/\" \"\"\r\n");
		}
		let existing = mailbox::list(&self.data_dir, &account);
		// LIST-EXTENDED (RFC 5258): `(SUBSCRIBED)` lists subscribed names,
		// whether or not the mailbox still exists.
		let extra: &[String] = if request.select_subscribed {
			&subscriptions
		} else {
			&[]
		};
		let qualifies = |name: &str, exists: bool| {
			(if request.select_subscribed {
				subscribed.contains(name)
			} else {
				exists
			}) && (!request.select_special_use
				|| (exists && !helpers::special_use_attribute(name).is_empty()))
		};
		let matches = |name: &str| {
			request
				.patterns
				.iter()
				.any(|pattern| list_pattern::matches(&request.reference, pattern, name))
		};
		let hidden = if !request.select_subscribed && !request.select_special_use {
			Hidden::Placeholder
		} else if request.recursive_match {
			Hidden::ChildInfo
		} else {
			Hidden::Skip
		};
		for entry in list_tree::select(&existing, extra, qualifies, matches, hidden) {
			let attributes = self.list_attributes(request, &entry, subscribed.contains(entry.name));
			let wire = self.mailbox_astring(entry.name);
			let child_info = if entry.child_info {
				child_info(request)
			} else {
				String::new()
			};
			response.push_str(&format!(
				"* LIST ({attributes}) \"/\" {wire}{child_info}\r\n"
			));
			// LIST-STATUS (RFC 5819): report the requested STATUS inline, for
			// a mailbox that exists.
			if !request.return_status.is_empty()
				&& entry.exists
				&& let Some(parts) = self.status_parts(&account, entry.name, &request.return_status)
			{
				response.push_str(&format!("* STATUS {wire} ({parts})\r\n"));
			}
		}
		response.push_str(&format!("{tag} OK LIST completed\r\n"));
		Output::text(response)
	}

	/// The attributes of one LIST line: special use, subscription, existence
	/// and children, each when the session or the request asks for it.
	fn list_attributes(
		&self,
		request: &ListCommand,
		entry: &Entry<'_>,
		subscribed: bool,
	) -> String {
		let wants = |attribute| self.imap4rev2 || request.return_attributes.contains(&attribute);
		let mut attributes = Vec::new();
		let special_use = helpers::special_use_attribute(entry.name);
		if entry.exists && !special_use.is_empty() && wants(ListAttribute::SpecialUse) {
			attributes.push(special_use);
		}
		if subscribed && wants(ListAttribute::Subscribed) {
			attributes.push("\\Subscribed");
		}
		if !entry.exists {
			// RFC 5258 §3: an extended LIST says `\NonExistent` (which
			// implies `\Noselect`); a plain one has only `\Noselect`.
			attributes.push(if request.extended || self.imap4rev2 {
				"\\NonExistent"
			} else {
				"\\Noselect"
			});
		}
		// CHILDREN (RFC 3348): a placeholder always says why it is listed.
		if entry.placeholder || wants(ListAttribute::Children) {
			attributes.push(if entry.has_children {
				"\\HasChildren"
			} else {
				"\\HasNoChildren"
			});
		}
		attributes.join(" ")
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
			"* STATUS {} ({parts})\r\n{tag} OK STATUS completed\r\n",
			self.mailbox_astring(mailbox)
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
				StatusItem::HighestModseq => {
					format!("HIGHESTMODSEQ {}", snapshot.highest_modseq())
				}
				StatusItem::AppendLimit => {
					// RFC 7889 §4: the same octet limit CAPABILITY
					// advertises, since it holds for every mailbox.
					format!("APPENDLIMIT {}", self.append_limit)
				}
			};
			parts.push_str(&rendered);
		}
		Some(parts)
	}
}

#[cfg(test)]
#[path = "list_status_tests_special_use.rs"]
mod special_use_selection;

#[cfg(test)]
#[path = "list_status_tests_root.rs"]
mod root_hierarchy;

#[cfg(test)]
#[path = "list_status_tests_hierarchy.rs"]
mod hierarchy;
