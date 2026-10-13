//! IMAP literal-bearing command handlers: APPEND (RFC 9051) and REPLACE
//! (RFC 8508). The command line is parsed elsewhere; these begin the
//! literal collection and finish once the payload arrives.

use super::mailbox::{self, Flag};
use super::state::State;
use super::{Output, PendingLiteral, Session};

/// Build the rejection `Output` for a literal-bearing command. When the
/// command used the non-synchronizing `{n+}` form, the client already sent
/// the payload, so the network layer must consume those bytes (RFC 7888 §4).
fn reject_literal(tag: &str, synchronizing: bool, size: usize, response: &str) -> Output {
	let mut output = Output::text(format!("{tag} {response}"));
	if !synchronizing {
		output.discard_literal = Some(size);
	}
	output
}

impl Session {
	pub(super) fn append_begin(
		&mut self,
		tag: &str,
		mailbox: &str,
		flag_tokens: &[String],
		size: usize,
		synchronizing: bool,
		utf8: bool,
	) -> Output {
		// A rejected `UTF8 (~{n+})` also drains the `)` after the literal.
		let wire_size = size + usize::from(utf8);
		let Some(account) = self.account().map(str::to_string) else {
			return reject_literal(tag, synchronizing, wire_size, "NO not authenticated\r\n");
		};
		// RFC 6855 §4: the UTF8 data item is only meaningful once enabled.
		if utf8 && !self.utf8_accept {
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"BAD UTF8 APPEND requires ENABLE UTF8=ACCEPT\r\n",
			);
		}
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"NO [TRYCREATE] no such mailbox\r\n",
			);
		}
		// Quota enforcement (RFC 9208): refuse before reading the literal.
		let projected =
			mailbox::account_usage(&self.data_dir, &account, &self.crypto) + size as u64;
		if self
			.effective_quota()
			.is_some_and(|limit| projected > limit)
		{
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"NO [OVERQUOTA] storage quota exceeded\r\n",
			);
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => {
					return reject_literal(
						tag,
						synchronizing,
						wire_size,
						"BAD unsupported flag\r\n",
					);
				}
			}
		}
		// A literal-bearing APPEND can only fail the keyword cap on Set
		// semantics (REPLACE has the same check via the replaced message);
		// refuse here so the client never sends the literal.
		if super::mailbox::count_keywords(&flags).is_none() {
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"BAD too many keywords (max {})\r\n",
			);
		}
		self.pending_append = Some(PendingLiteral {
			tag: tag.to_string(),
			mailbox: mailbox.to_string(),
			flags,
			replace: None,
		});
		// RFC 7888 §4: a non-synchronizing literal ({n+}) has no
		// continuation response. The client already sent the payload
		// in the same write as the command line, and Dovecot's
		// imaptest (and any IMAP4rev2 client using LITERAL+) crashes
		// when the server replies with `+ ready for literal data`
		// because its APPEND state machine expects the tagged
		// response next.
		let mut output = if synchronizing {
			Output::text("+ ready for literal data\r\n".to_string())
		} else {
			Output::text(String::new())
		};
		output.collect_literal = Some(size);
		if utf8 {
			output.literal_trailer = b")\r\n";
		}
		output
	}

	/// Begin REPLACE (RFC 8508): validate the source message and append target,
	/// then collect the literal. Requires a selected, writable mailbox.
	#[allow(clippy::too_many_arguments)]
	pub(super) fn replace_begin(
		&mut self,
		tag: &str,
		sequence: u32,
		mailbox: &str,
		flag_tokens: &[String],
		size: usize,
		uid: bool,
		synchronizing: bool,
	) -> Output {
		let resolved = {
			let State::Selected {
				snapshot,
				read_only,
				mailbox: selected,
				account,
			} = &self.state
			else {
				return reject_literal(tag, synchronizing, size, "NO no mailbox selected\r\n");
			};
			if *read_only {
				return reject_literal(tag, synchronizing, size, "NO mailbox is read-only\r\n");
			}
			let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
			let target_uid = if uid {
				match (1..=total)
					.find(|n| snapshot.by_sequence(*n).map(|m| m.uid) == Some(sequence))
				{
					Some(seq) => snapshot.by_sequence(seq).map(|m| m.uid).unwrap_or(0),
					None => {
						return reject_literal(tag, synchronizing, size, "NO no such message\r\n");
					}
				}
			} else if sequence >= 1 && sequence <= total {
				snapshot.by_sequence(sequence).map(|m| m.uid).unwrap_or(0)
			} else {
				return reject_literal(tag, synchronizing, size, "NO no such message\r\n");
			};
			if target_uid == 0 {
				return reject_literal(tag, synchronizing, size, "NO no such message\r\n");
			}
			(account.clone(), selected.clone(), target_uid)
		};
		let (account, selected, target_uid) = resolved;

		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return reject_literal(
				tag,
				synchronizing,
				size,
				"NO [TRYCREATE] no such mailbox\r\n",
			);
		}
		let projected =
			mailbox::account_usage(&self.data_dir, &account, &self.crypto) + size as u64;
		if self
			.effective_quota()
			.is_some_and(|limit| projected > limit)
		{
			return reject_literal(
				tag,
				synchronizing,
				size,
				"NO [OVERQUOTA] storage quota exceeded\r\n",
			);
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => {
					return reject_literal(tag, synchronizing, size, "BAD unsupported flag\r\n");
				}
			}
		}
		if super::mailbox::count_keywords(&flags).is_none() {
			return reject_literal(
				tag,
				synchronizing,
				size,
				"BAD too many keywords (max {})\r\n",
			);
		}
		self.pending_append = Some(PendingLiteral {
			tag: tag.to_string(),
			mailbox: mailbox.to_string(),
			flags,
			// Resolve the sequence to a UID at command start: a
			// concurrent session that expunges this message (or any
			// other change to the mailbox) between this point and
			// the literal read must not move the REPLACE target to
			// a different message.
			replace: Some((selected, target_uid)),
		});
		// See the matching note in `append_begin` above.
		let mut output = if synchronizing {
			Output::text("+ ready for literal data\r\n".to_string())
		} else {
			Output::text(String::new())
		};
		output.collect_literal = Some(size);
		output
	}

	/// Called by the network layer with the complete APPEND/REPLACE literal.
	pub fn literal_done(&mut self, data: &[u8]) -> Output {
		let Some(pending) = self.pending_append.take() else {
			return Output::text("* BAD unexpected literal\r\n".to_string());
		};
		let PendingLiteral {
			tag,
			mailbox,
			flags,
			replace,
		} = pending;
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let verb = if replace.is_some() {
			"REPLACE"
		} else {
			"APPEND"
		};
		let id = match mailbox::append(
			&self.data_dir,
			&account,
			&mailbox,
			&flags,
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
		let prelude = self.append_update_selected(&account, &mailbox);
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

	/// Refresh the live snapshot when the APPEND/REPLACE target is the
	/// SELECTed mailbox, and emit `* N EXISTS` so the client can keep its
	/// count in sync. Returns the empty string when no mailbox is selected
	/// or the target is a different mailbox (the append takes effect on
	/// disk, but the client will not see a stale count from this session).
	fn append_update_selected(&mut self, account: &str, mailbox: &str) -> String {
		// Names are cloned so the mutable borrow of `self.state` ends
		// before `open_snapshot` takes `&self`.
		let (selected, count_before) = match &self.state {
			State::Selected {
				snapshot,
				mailbox: selected,
				..
			} => (selected.clone(), snapshot.len()),
			_ => return String::new(),
		};
		if !selected.eq_ignore_ascii_case(mailbox) {
			return String::new();
		}
		let fresh = match self.open_snapshot(account, mailbox) {
			Ok(fresh) => fresh,
			Err(_) => return String::new(),
		};
		let count_after = fresh.len();
		let State::Selected { snapshot, .. } = &mut self.state else {
			return String::new();
		};
		*snapshot = fresh;
		if count_after <= count_before {
			return String::new();
		}
		format!("* {count_after} EXISTS\r\n")
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
		let expunge_line = removed_seq
			.map(|s| format!("* {s} EXPUNGE\r\n"))
			.unwrap_or_default();
		expunge_line
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
