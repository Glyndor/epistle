//! IMAP NOTIFY (RFC 5465).

use super::super::command::{NotifyEvent, NotifyRequest};
use super::mailbox::Snapshot;
use super::state::State;
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

	/// Poll for mailbox changes for a NOTIFY-enabled session, mirroring
	/// [`Self::check_idle`] but gated on active NOTIFY `selected` events rather
	/// than IDLE. Returns an unsolicited `* <n> EXISTS` when the selected mailbox
	/// gained or lost messages and the client asked for
	/// MessageNew/MessageExpunge.
	pub fn check_notify(&mut self) -> Option<Output> {
		if !self.notify_active() {
			return None;
		}
		let State::Selected {
			account,
			mailbox,
			snapshot,
			..
		} = &mut self.state
		else {
			return None;
		};
		let fresh = Snapshot::open(&self.data_dir, account, mailbox, &self.crypto).ok()?;
		if fresh.uid_validity() != snapshot.uid_validity() || fresh.len() != snapshot.len() {
			let exists = fresh.len();
			*snapshot = fresh;
			Some(Output::text(format!("* {exists} EXISTS\r\n")))
		} else {
			None
		}
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
