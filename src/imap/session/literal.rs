//! IMAP literal-bearing command handlers: APPEND (RFC 9051) and REPLACE
//! (RFC 8508). The command line is parsed elsewhere; these begin the
//! literal collection and finish once the payload arrives.

use super::mailbox::{self, Flag, Snapshot};
use super::{Output, PendingLiteral, Session, State};

impl Session {
	pub(super) fn append_begin(
		&mut self,
		tag: &str,
		mailbox: &str,
		flag_tokens: &[String],
		size: usize,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}
		// Quota enforcement (RFC 9208): refuse before reading the literal.
		let projected = mailbox::account_usage(&self.data_dir, &account) + size as u64;
		if projected > self.effective_quota() {
			return Output::text(format!("{tag} NO [OVERQUOTA] storage quota exceeded\r\n"));
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}
		self.pending_append = Some(PendingLiteral {
			tag: tag.to_string(),
			mailbox: mailbox.to_string(),
			flags,
			replace: None,
		});
		let mut output = Output::text("+ ready for literal data\r\n".to_string());
		output.collect_literal = Some(size);
		output
	}

	/// Begin REPLACE (RFC 8508): validate the source message and append target,
	/// then collect the literal. Requires a selected, writable mailbox.
	pub(super) fn replace_begin(
		&mut self,
		tag: &str,
		sequence: u32,
		mailbox: &str,
		flag_tokens: &[String],
		size: usize,
		uid: bool,
	) -> Output {
		let resolved = {
			let State::Selected {
				snapshot,
				read_only,
				mailbox: selected,
				account,
			} = &self.state
			else {
				return Output::text(format!("{tag} NO no mailbox selected\r\n"));
			};
			if *read_only {
				return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
			}
			let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
			let seq = if uid {
				match (1..=total)
					.find(|n| snapshot.by_sequence(*n).map(|m| m.uid) == Some(sequence))
				{
					Some(seq) => seq,
					None => return Output::text(format!("{tag} NO no such message\r\n")),
				}
			} else if sequence >= 1 && sequence <= total {
				sequence
			} else {
				return Output::text(format!("{tag} NO no such message\r\n"));
			};
			(account.clone(), selected.clone(), seq)
		};
		let (account, selected, seq) = resolved;

		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}
		let projected = mailbox::account_usage(&self.data_dir, &account) + size as u64;
		if projected > self.effective_quota() {
			return Output::text(format!("{tag} NO [OVERQUOTA] storage quota exceeded\r\n"));
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}
		self.pending_append = Some(PendingLiteral {
			tag: tag.to_string(),
			mailbox: mailbox.to_string(),
			flags,
			replace: Some((selected, seq)),
		});
		let mut output = Output::text("+ ready for literal data\r\n".to_string());
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
		let id = match mailbox::append(&self.data_dir, &account, &mailbox, &flags, data) {
			Ok(id) => id,
			Err(_) => return Output::text(format!("{tag} NO {verb} failed\r\n")),
		};
		// UIDPLUS: report the UIDVALIDITY and UID assigned (RFC 4315).
		let code = match mailbox::appenduid(&self.data_dir, &account, &mailbox, id) {
			Some((validity, uid)) => format!("[APPENDUID {validity} {uid}] "),
			None => String::new(),
		};
		match replace {
			None => Output::text(format!("{tag} OK {code}APPEND completed\r\n")),
			Some((selected, seq)) => self.replace_expunge(&tag, &account, &selected, seq, &code),
		}
	}

	/// Finish REPLACE: expunge the source message from the selected mailbox and
	/// refresh the live snapshot. The new message is already appended.
	fn replace_expunge(
		&mut self,
		tag: &str,
		account: &str,
		selected: &str,
		seq: u32,
		code: &str,
	) -> Output {
		let mut snapshot = match Snapshot::open(&self.data_dir, account, selected) {
			Ok(snapshot) => snapshot,
			Err(_) => return Output::text(format!("{tag} NO REPLACE failed\r\n")),
		};
		if snapshot.remove_at(seq).is_err() {
			return Output::text(format!("{tag} NO REPLACE failed\r\n"));
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
		Output::text(format!(
			"* {seq} EXPUNGE\r\n{tag} OK {code}REPLACE completed\r\n"
		))
	}
}
