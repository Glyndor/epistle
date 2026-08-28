//! IMAP IDLE state polling (RFC 9051 §6.4.7).

use super::mailbox::Snapshot;
use super::state::State;
use super::{Output, Session};

impl Session {
	/// Poll for mailbox changes during IDLE. Refreshes the snapshot and emits
	/// untagged EXISTS/FLAGS responses if the message count changed. Returns
	/// `None` when not in IDLE or no mailbox is selected.
	pub fn check_idle(&mut self) -> Option<Output> {
		self.idle_tag.as_ref()?;
		let State::Selected {
			account,
			mailbox,
			snapshot,
			..
		} = &mut self.state
		else {
			return None;
		};
		let fresh = match Snapshot::open(&self.data_dir, account, mailbox, &self.crypto) {
			Ok(s) => s,
			Err(_) => return None,
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
