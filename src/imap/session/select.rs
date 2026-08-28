//! IMAP SELECT/EXAMINE/CLOSE/UNSELECT (RFC 9051 §6.3, RFC 3691).

use super::state::State;
use super::{Output, Session, codes, mailbox};

impl Session {
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
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let snapshot =
			match mailbox::Snapshot::open(&self.data_dir, &account, mailbox, &self.crypto) {
				Ok(snapshot) => snapshot,
				Err(_) => return Output::text(format!("{tag} NO cannot open mailbox\r\n")),
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
		let response = format!(
			"* {count} EXISTS\r\n\
* OK [UIDVALIDITY {validity}] UIDs valid\r\n\
* OK [UIDNEXT {next}] predicted next UID\r\n\
* OK [MAILBOXID (M{validity})] mailbox object id\r\n\
* OK [HIGHESTMODSEQ {modseq}] highest mod-sequence\r\n\
* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n\
* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] limits\r\n\
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
		Output::text(response)
	}

	pub(super) fn close(&mut self, tag: &str) -> Output {
		match &self.state {
			State::Selected { account, .. } => {
				self.state = State::Authenticated {
					account: account.clone(),
				};
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
				Output::text(format!("{tag} OK UNSELECT completed\r\n"))
			}
			_ => Output::text(format!("{tag} BAD no mailbox selected\r\n")),
		}
	}
}
