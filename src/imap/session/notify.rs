//! IMAP NOTIFY (RFC 5465).

use super::super::command::{NotifyEvent, NotifyRequest};
use super::{Output, Session};

impl Session {
	/// NOTIFY (RFC 5465): record which selected-mailbox events the client wants
	/// pushed unsolicited. Other mailbox specifiers were accepted-and-ignored at
	/// parse time. Requires authentication.
	pub(super) fn notify(&mut self, tag: &str, request: NotifyRequest) -> Output {
		if self.account().is_none() {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		}
		match request {
			NotifyRequest::None => self.notify_selected = None,
			NotifyRequest::Set { selected, .. } => self.notify_selected = Some(selected),
		}
		Output::text(format!("{tag} OK NOTIFY completed\r\n"))
	}

	/// Poll for selected-mailbox changes when NOTIFY message events are active.
	/// Reports removals before arrivals, mirroring [`Self::check_idle`].
	pub fn check_notify(&mut self) -> Option<Output> {
		if !self.notify_active() {
			return None;
		}
		self.poll_selected_messages()
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
