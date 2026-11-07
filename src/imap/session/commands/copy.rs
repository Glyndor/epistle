//! IMAP COPY and MOVE command handlers (RFC 9051 §6.4.7, RFC 6851).

use super::super::super::command::SequenceSet;
use super::super::mailbox;
use super::super::state::State;
use super::super::{Output, Session};
use super::codes::copyuid_code;
use crate::imap::internal_date::InternalDate;

impl Session {
	pub(in crate::imap::session) fn copy(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		target: &str,
		uid: bool,
		remove_source: bool,
	) -> Output {
		let uidonly = self.uidonly;
		let data_dir = self.data_dir.clone();
		let crypto = self.crypto.clone();
		// Capture the SEARCHRES `$` set before the mutable borrow of
		// `self.state`. The saved set is always keyed by UID; for UID
		// commands the values are matched directly, and for non-UID
		// commands they are resolved through the snapshot to current
		// sequence numbers (expunged entries drop out, per RFC 5182 §2.1).
		let saved_search = self.saved_search.clone();
		// Cloned before `self.state` is borrowed mutably below.
		let training = self.training.clone();
		let State::Selected {
			account,
			snapshot,
			read_only,
			mailbox: source_mailbox,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if remove_source && *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		let account = account.clone();
		let source_mailbox = source_mailbox.clone();
		if !mailbox::exists(&data_dir, &account, target) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}
		// Resolve the SEARCHRES `$` placeholder against this snapshot. The
		// saved set is always keyed by UID; mapping through the snapshot
		// drops expunged entries and produces the kind of values the loop
		// expects (UIDs for UID commands, seqnos for non-UID commands).
		let saved = match saved_search.as_ref() {
			Some(saved) if saved.are_uids == uid => {
				if uid {
					saved.uids.clone()
				} else {
					saved
						.uids
						.iter()
						.filter_map(|u| snapshot.sequence_of_uid(*u))
						.collect()
				}
			}
			_ => Vec::new(),
		};

		let total = snapshot.max_identifier(false);
		let maximum = snapshot.max_identifier(uid);
		let mut matched = Vec::new();
		let mut source_uids = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if sequence.contains(selector, maximum, &saved) {
				matched.push(sequence_number);
				source_uids.push(message.uid);
			}
		}

		// Copy all before removing any: a failed copy must not lose mail.
		let mut dest_ids = Vec::new();
		for sequence_number in &matched {
			let Some(message) = snapshot.by_sequence(*sequence_number) else {
				return Output::text(format!("{tag} NO message vanished\r\n"));
			};
			let data = match snapshot.read(message) {
				Ok(data) => data,
				Err(_) => return Output::text(format!("{tag} NO message unavailable\r\n")),
			};
			// RFC 9051 §6.4.7: the copy keeps the source's INTERNALDATE.
			let date = InternalDate {
				time: message.internal_date,
				zone: message.internal_zone,
			};
			let copied = mailbox::append_dated(
				&data_dir,
				&account,
				target,
				&message.flags,
				Some(date),
				&data,
				&crypto,
			);
			match copied {
				Ok(id) => dest_ids.push(id),
				Err(_) => return Output::text(format!("{tag} NO copy failed\r\n")),
			}
		}

		// UIDPLUS: the source and destination UID sets (RFC 4315).
		let copyuid = copyuid_code(&data_dir, &account, target, &source_uids, &dest_ids);

		let mut response = String::new();
		if remove_source {
			// RFC 6851 §4.3: MOVE reports COPYUID in an untagged OK before
			// the expunges, since by the tagged reply the source UIDs are
			// gone.
			if !copyuid.is_empty() {
				response.push_str(&format!("* OK {copyuid}moved\r\n"));
			}
			// Remove bottom-up so earlier sequence numbers stay valid, but
			// emit EXPUNGE top-down with renumber-correct values.
			for (offset, sequence_number) in matched.iter().enumerate() {
				let current = sequence_number - u32::try_from(offset).unwrap_or(0);
				if snapshot.remove_at(current).is_err() {
					return Output::text(format!("{tag} NO move failed\r\n"));
				}
				if !uidonly {
					response.push_str(&format!("* {current} EXPUNGE\r\n"));
				}
			}
			// UIDONLY: report removals as a single VANISHED with UIDs.
			if uidonly && !source_uids.is_empty() {
				response.push_str(&format!(
					"* VANISHED {}\r\n",
					super::codes::uid_set(&source_uids)
				));
			}
		}
		// A message that goes into Junk, or a move out of it, teaches the
		// account corpus. The queue never waits, so the reply does not
		// depend on it.
		if let Some(queue) = &training
			&& let Some(signal) =
				super::super::super::junk_moves::move_signal(&source_mailbox, target, remove_source)
			&& let Some(dir) = mailbox::mailbox_dir(&data_dir, &account, target)
		{
			super::super::super::junk_moves::enqueue_move(
				queue,
				&account,
				signal,
				&dir,
				&dest_ids,
				&mut queue.command_budget(),
			);
		}
		// A copy into the selected mailbox, or a change another session
		// made meanwhile, reaches the client before the tagged reply.
		response.push_str(&self.sync_selected(true));
		let (code, verb) = if remove_source {
			("", "MOVE")
		} else {
			(copyuid.as_str(), "COPY")
		};
		response.push_str(&format!("{tag} OK {code}{verb} completed\r\n"));
		Output::text(response)
	}
}
