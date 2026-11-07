//! Storing the message an APPEND or REPLACE carried: the literal that
//! arrived is written to the mailbox and the client's view of it is brought
//! up to date. [`super::literal`] starts the exchange.

use super::super::mailbox;
use super::super::state::State;
use super::super::{Output, PendingLiteral, Session};

impl Session {
	/// Called by the network layer with the complete APPEND/REPLACE literal.
	pub fn literal_done(&mut self, data: &[u8]) -> Output {
		let Some(pending) = self.pending_append.take() else {
			return Output::text("* BAD unexpected literal\r\n".to_string());
		};
		let PendingLiteral {
			tag,
			mailbox,
			flags,
			date,
			replace,
			binary,
		} = pending;
		let encoded = binary
			.then(|| crate::imap::binary_append::encode_binary_parts(data))
			.flatten();
		let data = encoded.as_deref().unwrap_or(data);
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let verb = if replace.is_some() {
			"REPLACE"
		} else {
			"APPEND"
		};
		// The dedup fast path for client-side APPENDs to the `Sent`
		// folder: when the literal carries a Message-ID the server
		// already saved in the last 24 hours, the server returns the
		// existing UID as if the APPEND had landed, but does not
		// write a second copy. REPLACE always stores the literal as
		// the replacement of its target message; the dedup is an
		// APPEND-only path so the IMAP4rev2 sequence number for the
		// replacement stays coherent.
		if replace.is_none()
			&& mailbox.eq_ignore_ascii_case("Sent")
			&& let Some(message_id) = crate::storage::first_message_id(data)
		{
			let dedup_outcome = self.append_skip_stored_sent(&tag, &account, &mailbox, &message_id);
			match dedup_outcome {
				Some(output) => return output,
				None => {
					// Guard said "not recent": fall through to the
					// normal APPEND path.
				}
			}
		}
		let id = match mailbox::append_dated(
			&self.data_dir,
			&account,
			&mailbox,
			&flags,
			date,
			data,
			&self.crypto,
		) {
			Ok(id) => id,
			Err(_) => return Output::text(format!("{tag} NO {verb} failed\r\n")),
		};
		// UIDPLUS: report the UIDVALIDITY and UID assigned (RFC 4315).
		let code = match mailbox::appenduid(&self.data_dir, &account, &mailbox, id) {
			Some((validity, uid)) => format!("[APPENDUID {validity} {uid}] "),
			None => String::new(),
		};
		// RFC 9051 §7.4: a successful APPEND (or the append half of REPLACE)
		// on the SELECTed mailbox must announce the new message count via an
		// untagged `* N EXISTS` before the tagged completion. Dovecot's
		// imaptest maintains the mailbox's per-session message count and
		// the per-mailbox keyword set from the untagged responses, and
		// surfaces the missing line as `Missing N untagged replies`.
		// The live snapshot is refreshed here so a STORE or FETCH that
		// follows the APPEND inside the same command sees the new message.
		let prelude = self.append_update_selected(&mailbox);
		match replace {
			None => Output::text(format!("{prelude}{tag} OK {code}APPEND completed\r\n")),
			Some((selected, seq)) => {
				let expunge = self.replace_expunge_response(&tag, &account, &selected, seq);
				Output::text(format!(
					"{prelude}{expunge}{tag} OK {code}REPLACE completed\r\n"
				))
			}
		}
	}

	/// Try the dedup fast path: when the guard says the server already
	/// stored a copy of `message_id` in the last 24 hours and the
	/// on-disk scan still finds it in `Sent`, return an `OK
	/// [APPENDUID ...]` reply that points the client at the existing
	/// copy. Returns `None` when the guard has no entry or the on-disk
	/// scan fails (the caller falls through to the normal APPEND
	/// path).
	fn append_skip_stored_sent(
		&mut self,
		tag: &str,
		account: &str,
		mailbox: &str,
		message_id: &str,
	) -> Option<Output> {
		let guard = crate::storage::save_sent::Guard::open(&self.data_dir, account)
			.map_err(|error| {
				tracing::warn!(
					account = %crate::log_id::account(account),
					%error,
					"save_sent: cannot open the dedup guard; falling back to APPEND"
				);
				error
			})
			.ok()?;
		guard.is_recent(message_id).ok()?.as_ref()?;
		let (validity, uid) =
			mailbox::appenduid_for_message_id(&self.data_dir, account, mailbox, message_id)?;
		let code = format!("[APPENDUID {validity} {uid}] ");
		let prelude = self.append_update_selected(mailbox);
		Some(Output::text(format!(
			"{prelude}{tag} OK {code}APPEND completed\r\n"
		)))
	}

	/// Bring the client up to date when the APPEND/REPLACE target is the
	/// SELECTed mailbox, so it hears `* N EXISTS` for the new message and
	/// anything else that changed, and a STORE or FETCH that follows sees
	/// the new message. Returns the empty string when no mailbox is
	/// selected or the target is a different one.
	fn append_update_selected(&mut self, mailbox: &str) -> String {
		match &self.state {
			State::Selected {
				mailbox: selected, ..
			} if selected.eq_ignore_ascii_case(mailbox) => self.sync_selected(true),
			_ => String::new(),
		}
	}

	/// Finish REPLACE: expunge the source message from the selected mailbox and
	/// refresh the live snapshot. The new message is already appended.
	fn replace_expunge_response(
		&mut self,
		tag: &str,
		account: &str,
		selected: &str,
		uid: u32,
	) -> String {
		let mut snapshot = match self.open_snapshot(account, selected) {
			Ok(snapshot) => snapshot,
			Err(_) => return format!("{tag} NO REPLACE failed\r\n"),
		};
		// Compute the sequence number the target occupies in the current
		// snapshot before we remove it. When the target is no longer
		// there (a concurrent session already expunged it) the result
		// is `None` and we skip the EXPUNGE line.
		let removed_seq = snapshot
			.messages()
			.position(|m| m.uid == uid)
			.map(|p| u32::try_from(p + 1).unwrap_or(u32::MAX));
		// Remove by UID, not by sequence: a concurrent expunge in
		// another session could have removed the message that was at
		// this UID's slot, but no other UID ever takes the same value.
		// Removing by sequence here would silently delete whichever
		// message now occupies the slot. REPLACE also does not require
		// the client to have set \Deleted on the target, so the
		// generic expunge path (which only removes \Deleted messages)
		// would not work.
		if snapshot.remove_uids(&[uid]).is_err() {
			return format!("{tag} NO REPLACE failed\r\n");
		}
		// Keep the live selected snapshot consistent with the expunge.
		if let State::Selected {
			mailbox: live,
			snapshot: live_snapshot,
			..
		} = &mut self.state
			&& live == selected
		{
			*live_snapshot = snapshot;
		}
		// Report the expunged sequence number: the slot the target
		// occupied before the removal. With the original message
		// already gone (reordered by a concurrent expunge) this is
		// `None` and we skip the EXPUNGE line; the UID-based
		// deletion above keeps the target correct regardless.
		removed_seq
			.map(|s| format!("* {s} EXPUNGE\r\n"))
			.unwrap_or_default()
	}

	/// Reject an APPEND/REPLACE whose literal was not followed by CRLF
	/// (RFC 9051 §6.3.2). The literal body is discarded and the message
	/// is not stored: this is called by the server after it has read both
	/// the literal bytes and the two trailer bytes, before any side effect
	/// on the mailbox.
	pub fn literal_bad_trailer(&mut self) -> Output {
		let Some(pending) = self.pending_append.take() else {
			return Output::text("* BAD unexpected literal\r\n".to_string());
		};
		let verb = if pending.replace.is_some() {
			"REPLACE"
		} else {
			"APPEND"
		};
		Output::text(format!(
			"{} BAD {} literal must be followed by CRLF\r\n",
			pending.tag, verb
		))
	}
}
