//! IMAP IDLE state polling (RFC 9051 §6.3.13).

use super::{Output, Session};

impl Session {
	/// Poll for mailbox changes during IDLE. Removed messages are reported
	/// before flag changes and arrivals so the client's sequence numbers
	/// follow the snapshot. Returns `None` when not in IDLE, no mailbox is
	/// selected, or nothing changed.
	pub fn check_idle(&mut self) -> Option<Output> {
		self.idle_tag.as_ref()?;
		self.poll_selected_messages(true)
	}

	/// The changes to the SELECTed mailbox as one unsolicited output, with
	/// flag changes only when `report_flags`.
	pub(super) fn poll_selected_messages(&mut self, report_flags: bool) -> Option<Output> {
		let response = self.sync_selected(report_flags);
		if response.is_empty() {
			None
		} else {
			Some(Output::text(response))
		}
	}
}
