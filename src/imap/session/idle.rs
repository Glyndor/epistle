//! IMAP IDLE state polling (RFC 9051 §6.4.7).

use super::state::State;
use super::{Output, Session};

impl Session {
	/// Poll for mailbox changes during IDLE. Refreshes the snapshot and emits
	/// untagged EXISTS/FLAGS responses if the message count changed. Returns
	/// `None` when not in IDLE or no mailbox is selected.
	pub fn check_idle(&mut self) -> Option<Output> {
		self.idle_tag.as_ref()?;
		// Names are cloned so the mutable borrow of `self.state` ends before
		// `open_snapshot` takes `&self`.
		let (account, mailbox) = match &self.state {
			State::Selected {
				account, mailbox, ..
			} => (account.clone(), mailbox.clone()),
			_ => return None,
		};
		let fresh = self.open_snapshot(&account, &mailbox).ok()?;
		let State::Selected { snapshot, .. } = &mut self.state else {
			return None;
		};
		if fresh.uid_validity() != snapshot.uid_validity() || fresh.len() != snapshot.len() {
			let exists = fresh.len();
			*snapshot = fresh;
			Some(Output::text(format!("* {exists} EXISTS\r\n")))
		} else {
			None
		}
	}
}
