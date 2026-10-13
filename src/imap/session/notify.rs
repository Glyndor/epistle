//! IMAP NOTIFY (RFC 5465).

use super::super::command::{NotifyEvent, NotifyGroup, NotifyMailboxes, NotifyRequest, StatusItem};
use super::{Output, Session, State, mailbox};

impl Session {
	/// NOTIFY (RFC 5465): record which selected-mailbox events the client wants
	/// pushed unsolicited. With `SET STATUS`, report the current state of every
	/// other mailbox the request names (§5.1). Requires authentication.
	pub(super) fn notify(&mut self, tag: &str, request: NotifyRequest) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let mut response = String::new();
		match request {
			NotifyRequest::None => self.notify_selected = None,
			NotifyRequest::Set {
				status,
				selected,
				others,
			} => {
				if status {
					response = self.notify_status(&account, &others);
				}
				self.notify_selected = Some(selected);
			}
		}
		response.push_str(&format!("{tag} OK NOTIFY completed\r\n"));
		Output::text(response)
	}

	/// One STATUS reply per mailbox the groups name, the selected one aside:
	/// MESSAGES, UIDNEXT and UIDVALIDITY, plus HIGHESTMODSEQ when the group
	/// asks for FlagChange. A group with no events reports nothing.
	fn notify_status(&self, account: &str, groups: &[NotifyGroup]) -> String {
		let selected = match &self.state {
			State::Selected { mailbox, .. } => Some(mailbox.as_str()),
			_ => None,
		};
		let mut seen: Vec<String> = Vec::new();
		let mut response = String::new();
		for group in groups.iter().filter(|group| !group.events.is_empty()) {
			let mut items = vec![
				StatusItem::Messages,
				StatusItem::Uidnext,
				StatusItem::Uidvalidity,
			];
			if group.events.contains(&NotifyEvent::FlagChange) {
				items.push(StatusItem::HighestModseq);
			}
			for name in self.notify_mailboxes(account, &group.mailboxes) {
				if Some(name.as_str()) == selected || seen.contains(&name) {
					continue;
				}
				if let Some(parts) = self.status_parts(account, &name, &items) {
					let name_wire = self.mailbox_astring(&name);
					response.push_str(&format!("* STATUS {name_wire} ({parts})\r\n"));
				}
				seen.push(name);
			}
		}
		response
	}

	/// The existing mailboxes a NOTIFY mailbox specifier covers.
	fn notify_mailboxes(&self, account: &str, filter: &NotifyMailboxes) -> Vec<String> {
		let all = mailbox::list(&self.data_dir, account);
		let canonical = |name: &str| {
			all.iter()
				.find(|known| {
					known.as_str() == name
						|| (known.as_str() == "INBOX" && name.eq_ignore_ascii_case("INBOX"))
				})
				.cloned()
		};
		match filter {
			NotifyMailboxes::Inboxes => vec!["INBOX".to_string()],
			NotifyMailboxes::Personal => all.clone(),
			NotifyMailboxes::Subscribed => mailbox::list_subscribed(&self.data_dir, account)
				.iter()
				.filter_map(|name| canonical(name))
				.collect(),
			NotifyMailboxes::Mailboxes(names) => {
				names.iter().filter_map(|name| canonical(name)).collect()
			}
			NotifyMailboxes::Subtree(roots) => all
				.iter()
				.filter(|name| {
					roots.iter().any(|root| {
						canonical(root).is_some_and(|root| {
							**name == root
								|| name
									.strip_prefix(root.as_str())
									.is_some_and(|rest| rest.starts_with('/'))
						})
					})
				})
				.cloned()
				.collect(),
		}
	}

	/// Poll for selected-mailbox changes when NOTIFY message events are active.
	/// Reports removals before arrivals, mirroring [`Self::check_idle`].
	pub fn check_notify(&mut self) -> Option<Output> {
		if !self.notify_active() {
			return None;
		}
		let flags = self
			.notify_selected
			.as_ref()
			.is_some_and(|events| events.contains(&NotifyEvent::FlagChange));
		self.poll_selected_messages(flags)
	}

	/// Whether this session has NOTIFY enabled with selected-mailbox message
	/// events, so the server loop should poll between commands.
	pub fn notify_active(&self) -> bool {
		self.notify_selected.as_ref().is_some_and(|events| {
			events
				.iter()
				.any(|e| matches!(e, NotifyEvent::MessageNew | NotifyEvent::MessageExpunge))
		})
	}
}
