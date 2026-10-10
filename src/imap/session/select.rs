//! IMAP SELECT/EXAMINE/CLOSE/UNSELECT (RFC 9051 §6.3, RFC 3691).

use super::state::State;
use super::{Output, Session, codes, mailbox};

/// Move a Selected state to Authenticated on a failed SELECT/EXAMINE, keeping
/// the authenticated account binding intact. Returns `true` when a mailbox
/// was selected and the caller must include `[CLOSED]` in its tagged NO
/// response (RFC 9051 §6.3.2 / §7.1).
fn deselect_for_failed_select(state: &mut State) -> bool {
	match state {
		State::Selected { account, .. } => {
			let prior = std::mem::take(account);
			*state = State::Authenticated { account: prior };
			true
		}
		_ => false,
	}
}

impl Session {
	pub(super) fn check(&self, tag: &str) -> Output {
		if matches!(self.state, State::Selected { .. }) {
			Output::text(format!("{tag} OK CHECK completed\r\n"))
		} else {
			Output::text(format!("{tag} BAD no mailbox selected\r\n"))
		}
	}

	pub(super) fn select(
		&mut self,
		tag: &str,
		mailbox: &str,
		read_only: bool,
		qresync: Option<(u32, u64)>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			// RFC 9051 §6.3.2: a failed SELECT deselects. The NO response
			// carries [CLOSED] when a mailbox was selected beforehand, so a
			// client that races a SELECT sees the boundary between the two.
			let closed = deselect_for_failed_select(&mut self.state);
			self.saved_search = None;
			return Output::text(format!(
				"{tag} NO {}no such mailbox\r\n",
				if closed { "[CLOSED] " } else { "" }
			));
		}
		let snapshot = match self.open_snapshot(&account, mailbox) {
			Ok(snapshot) => snapshot,
			Err(_) => {
				// Same deselection discipline as a missing mailbox: a snapshot
				// that cannot be opened is not the selected mailbox, and the
				// session moves back to authenticated.
				let closed = deselect_for_failed_select(&mut self.state);
				self.saved_search = None;
				return Output::text(format!(
					"{tag} NO {}cannot open mailbox\r\n",
					if closed { "[CLOSED] " } else { "" }
				));
			}
		};
		// QRESYNC: report vanished UIDs, but only if UIDVALIDITY still matches.
		let vanished = match qresync {
			Some((uid_validity, modseq)) if uid_validity == snapshot.uid_validity() => {
				let uids = snapshot.vanished_since(modseq);
				if uids.is_empty() {
					String::new()
				} else {
					format!("* VANISHED (EARLIER) {}\r\n", codes::uid_set(&uids))
				}
			}
			_ => String::new(),
		};
		// FLAGS advertises the system flags plus every user keyword currently
		// in use in the mailbox (RFC 9051 §6.3.1: the response lists the
		// flags the client can set on a message). PERMANENTFLAGS carries the
		// five system flags and the `\*` marker so the client may introduce
		// new keywords via STORE.
		let keyword_tokens: Vec<String> = {
			let mut all = Vec::new();
			for message in snapshot.messages() {
				for keyword in mailbox::keywords_in(&message.flags) {
					all.push(keyword.as_str().to_string());
				}
			}
			let mut seen: Vec<String> = Vec::new();
			all.retain(|name| {
				let fresh = !seen.iter().any(|s| s.eq_ignore_ascii_case(name));
				if fresh {
					seen.push(name.clone());
				}
				fresh
			});
			all
		};
		let flags_line = if keyword_tokens.is_empty() {
			"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n".to_string()
		} else {
			format!(
				"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft {})\r\n",
				keyword_tokens.join(" ")
			)
		};
		// The store does not assign recent-message ownership to sessions.
		// RFC 3501 permits reporting no recent messages to any client.
		let mut legacy = String::new();
		if !self.imap4rev2 {
			legacy.push_str("* 0 RECENT\r\n");
			if let Some(first) = snapshot
				.messages()
				.position(|m| !m.flags.contains(&mailbox::Flag::Seen))
			{
				legacy.push_str(&format!(
					"* OK [UNSEEN {}] first unseen message\r\n",
					first + 1
				));
			}
		}
		let response = format!(
			"* {count} EXISTS\r\n\
			 {legacy}\
			 * OK [UIDVALIDITY {validity}] UIDs valid\r\n\
			 * OK [UIDNEXT {next}] predicted next UID\r\n\
			 * OK [MAILBOXID (M{validity})] mailbox object id\r\n\
			 * OK [HIGHESTMODSEQ {modseq}] highest mod-sequence\r\n\
			 {flags_line}\
			 * OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)] limits\r\n\
			 {vanished}{tag} OK [{mode}] {verb} completed\r\n",
			count = snapshot.len(),
			validity = snapshot.uid_validity(),
			next = snapshot.uid_next(),
			modseq = snapshot.highest_modseq(),
			mode = if read_only { "READ-ONLY" } else { "READ-WRITE" },
			verb = if read_only { "EXAMINE" } else { "SELECT" },
		);
		self.state = State::Selected {
			account,
			mailbox: mailbox.to_string(),
			snapshot,
			read_only,
		};
		// RFC 5182 §2.1: a successful SELECT resets the search result
		// variable to the empty sequence. Per #976 we also clear on
		// CLOSE and UNSELECT, both of which leave the selected state.
		self.saved_search = None;
		Output::text(response)
	}

	pub(super) fn close(&mut self, tag: &str) -> Output {
		match &mut self.state {
			State::Selected {
				snapshot,
				read_only,
				account,
				..
			} => {
				// RFC 9051 §6.4.1: CLOSE on a read-write selection silently
				// expunges every \Deleted message; on EXAMINE (read-only) it
				// expunges nothing. Either way no untagged EXPUNGE responses
				// are sent, the session returns to authenticated.
				if !*read_only {
					let _ = snapshot.expunge();
				}
				let prev = std::mem::take(account);
				self.state = State::Authenticated { account: prev };
				self.saved_search = None;
				Output::text(format!("{tag} OK CLOSE completed\r\n"))
			}
			_ => Output::text(format!("{tag} BAD no mailbox selected\r\n")),
		}
	}

	/// UNSELECT (RFC 3691): leave the mailbox without expunging \Deleted.
	pub(super) fn unselect(&mut self, tag: &str) -> Output {
		match &self.state {
			State::Selected { account, .. } => {
				self.state = State::Authenticated {
					account: account.clone(),
				};
				self.saved_search = None;
				Output::text(format!("{tag} OK UNSELECT completed\r\n"))
			}
			_ => Output::text(format!("{tag} BAD no mailbox selected\r\n")),
		}
	}
}
