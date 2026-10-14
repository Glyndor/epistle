//! Untagged updates that bring the client's view of the SELECTed mailbox
//! up to date with what other sessions and deliveries did to it
//! (RFC 9051 §7.4.1, §7.5.1, §7.5.2; RFC 3501 §7.4.1).
//!
//! The session's snapshot is the mailbox as the client knows it: its
//! sequence numbers are the ones the client uses. Replacing it with the
//! on-disk state is only valid together with the responses that tell the
//! client what changed, so every refresh goes through here.

use std::collections::HashMap;

use super::fetchstore::collect_mailbox_keywords;
use super::mailbox::{Snapshot, render_flags};
use super::select::flags_line_for;
use super::state::State;
use super::{Session, codes};

impl Session {
	/// Re-read the SELECTed mailbox and return the untagged responses that
	/// describe the difference: EXPUNGE (VANISHED under UIDONLY) for each
	/// removed message, a FLAGS line when a keyword is new to the client,
	/// FETCH FLAGS for each flag change when `report_flags`, and EXISTS
	/// when messages arrived. Empty when nothing changed, no mailbox is
	/// selected, or the mailbox cannot be read.
	///
	/// Expunges renumber the mailbox, so this must not run while answering
	/// FETCH, STORE or SEARCH (RFC 3501 §7.4.1). Without `report_flags` the
	/// client's view of the flags is kept, so a later call reports them.
	pub(super) fn sync_selected(&mut self, report_flags: bool) -> String {
		let Some((account, mailbox)) = self.selected_pair() else {
			return String::new();
		};
		let Ok(mut fresh) = self.open_snapshot(&account, &mailbox) else {
			return String::new();
		};
		let uidonly = self.uidonly;
		let State::Selected { snapshot, .. } = &mut self.state else {
			return String::new();
		};
		if !report_flags {
			fresh.keep_flags_of(snapshot);
		}
		let response = changes(snapshot, &fresh, uidonly);
		*snapshot = fresh;
		response
	}
}

/// The responses that turn `known` into `fresh`, in the order the client
/// must apply them: removals (highest sequence first, so each number is
/// still valid when it arrives), flag changes numbered after the
/// removals, then the new count.
fn changes(known: &Snapshot, fresh: &Snapshot, uidonly: bool) -> String {
	let mut response = String::new();
	let replaced = fresh.uid_validity() != known.uid_validity();
	let current: HashMap<u32, &super::mailbox::MessageRef> = fresh
		.messages()
		.map(|message| (message.uid, message))
		.collect();
	let mut removed = Vec::new();
	let mut survivors = Vec::new();
	for (index, message) in known.messages().enumerate() {
		match current.get(&message.uid) {
			Some(now) if !replaced => survivors.push((message, *now)),
			_ => removed.push((u32::try_from(index + 1).unwrap_or(u32::MAX), message.uid)),
		}
	}
	if uidonly && !removed.is_empty() {
		let uids: Vec<u32> = removed.iter().map(|(_, uid)| *uid).collect();
		response.push_str(&format!("* VANISHED {}\r\n", codes::uid_set(&uids)));
	} else {
		for (sequence, _) in removed.iter().rev() {
			response.push_str(&format!("* {sequence} EXPUNGE\r\n"));
		}
	}
	let known_keywords = collect_mailbox_keywords(known);
	let fresh_keywords = collect_mailbox_keywords(fresh);
	if fresh_keywords
		.iter()
		.any(|name| !known_keywords.iter().any(|k| k.eq_ignore_ascii_case(name)))
	{
		response.push_str(&format!("* {}", flags_line_for(&fresh_keywords)));
	}
	for (index, (before, now)) in survivors.iter().enumerate() {
		if super::super::flags::flags_equal(&before.flags, &now.flags) {
			continue;
		}
		let flags = render_flags(&now.flags);
		if uidonly {
			response.push_str(&format!("* UIDFETCH {} (FLAGS {flags})\r\n", now.uid));
		} else {
			response.push_str(&format!("* {} FETCH (FLAGS {flags})\r\n", index + 1));
		}
	}
	if fresh.len() > survivors.len() {
		response.push_str(&format!("* {} EXISTS\r\n", fresh.len()));
	}
	response
}
