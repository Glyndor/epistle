//! IMAP IDLE state polling (RFC 9051 §6.4.7).

use std::collections::HashSet;

use super::state::State;
use super::{Output, Session};

impl Session {
	/// Poll for mailbox changes during IDLE. Removed messages are reported
	/// before arrivals so the client's sequence numbers follow the snapshot.
	/// Returns `None` when not in IDLE or no mailbox is selected.
	pub fn check_idle(&mut self) -> Option<Output> {
		self.idle_tag.as_ref()?;
		self.poll_selected_messages()
	}

	pub(super) fn poll_selected_messages(&mut self) -> Option<Output> {
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
		let fresh_uids: HashSet<u32> = fresh.messages().map(|message| message.uid).collect();
		let removed: Vec<(u32, u32)> = snapshot
			.messages()
			.enumerate()
			.filter(|(_, message)| !fresh_uids.contains(&message.uid))
			.filter_map(|(index, message)| {
				u32::try_from(index + 1)
					.ok()
					.map(|seqno| (seqno, message.uid))
			})
			.collect();
		let mut response = String::new();
		if self.uidonly && !removed.is_empty() {
			let uids: Vec<u32> = removed.iter().map(|(_, uid)| *uid).collect();
			response.push_str(&format!("* VANISHED {}\r\n", super::codes::uid_set(&uids)));
		} else {
			// Descending removals keep all lower original sequence numbers valid.
			for (seqno, _) in removed.iter().rev() {
				response.push_str(&format!("* {seqno} EXPUNGE\r\n"));
			}
		}
		let remaining = snapshot.len() - removed.len();
		if fresh.len() > remaining || fresh.uid_validity() != snapshot.uid_validity() {
			response.push_str(&format!("* {} EXISTS\r\n", fresh.len()));
		}
		*snapshot = fresh;
		if response.is_empty() {
			None
		} else {
			Some(Output::text(response))
		}
	}
}
