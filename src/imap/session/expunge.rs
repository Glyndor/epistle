//! IMAP EXPUNGE and UID EXPUNGE (RFC 9051 §6.4.5, RFC 4315).

use super::super::command::SequenceSet;
use super::codes::uid_set;
use super::mailbox::Flag;
use super::state::State;
use super::{Output, Session};

impl Session {
	pub(super) fn expunge(&mut self, tag: &str) -> Output {
		let uidonly = self.uidonly;
		let State::Selected {
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		// UIDONLY reports VANISHED with UIDs, captured before they are removed.
		let deleted_uids: Vec<u32> = snapshot
			.messages()
			.filter(|m| m.flags.contains(&Flag::Deleted))
			.map(|m| m.uid)
			.collect();
		match snapshot.expunge() {
			Ok(expunged) => {
				let response = expunge_response(uidonly, &expunged, &deleted_uids);
				Output::text(format!("{response}{tag} OK EXPUNGE completed\r\n"))
			}
			Err(_) => Output::text(format!("{tag} NO EXPUNGE failed\r\n")),
		}
	}

	pub(super) fn uid_expunge(&mut self, tag: &str, sequence: &SequenceSet) -> Output {
		let uidonly = self.uidonly;
		// Capture the SEARCHRES `$` set before the mutable borrow of `self.state`.
		let saved = self.saved_seqnos_for(true);
		let State::Selected {
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		let max_uid = snapshot.messages().map(|m| m.uid).max().unwrap_or(0);
		let uids: Vec<u32> = snapshot
			.messages()
			.map(|m| m.uid)
			.filter(|uid| sequence.contains(*uid, max_uid, &saved))
			.collect();
		// The UIDs actually removed are the in-set ones flagged \Deleted.
		let deleted_uids: Vec<u32> = snapshot
			.messages()
			.filter(|m| m.flags.contains(&Flag::Deleted) && uids.contains(&m.uid))
			.map(|m| m.uid)
			.collect();
		match snapshot.expunge_uids(&uids) {
			Ok(expunged) => {
				let response = expunge_response(uidonly, &expunged, &deleted_uids);
				Output::text(format!("{response}{tag} OK EXPUNGE completed\r\n"))
			}
			Err(_) => Output::text(format!("{tag} NO EXPUNGE failed\r\n")),
		}
	}
}

/// Build the untagged expunge output: per-message `EXPUNGE` lines normally, or
/// a single `VANISHED` with the removed UIDs under UIDONLY (RFC 9586).
fn expunge_response(uidonly: bool, expunged: &[u32], deleted_uids: &[u32]) -> String {
	if uidonly {
		if deleted_uids.is_empty() {
			return String::new();
		}
		return format!("* VANISHED {}\r\n", uid_set(deleted_uids));
	}
	expunged
		.iter()
		.map(|seq| format!("* {seq} EXPUNGE\r\n"))
		.collect()
}
