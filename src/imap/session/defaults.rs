//! Complete authentication only after the personal mailboxes are available.

use super::{Output, Session, State, mailbox};

impl Session {
	pub(super) fn auth_success(&mut self, tag: &str, account: String, completion: &str) -> Output {
		if let Err(error) = mailbox::ensure_defaults(&self.data_dir, &account) {
			tracing::error!(%error, "cannot initialize personal mailboxes");
			return Output::text(format!(
				"{tag} NO [SERVERBUG] cannot initialize mailboxes\r\n"
			));
		}
		// `[server] max_connections_per_account` (default 10 per (account,
		// IP) and 50 in total). Applied after the directory admits the
		// credentials but before the mailbox is opened so a refused
		// connection does not leave mailboxes around. The slot is held by
		// the session for the lifetime of the connection; the IMAP
		// listener takes it at the same point it would call `take` on any
		// owned guard, so the count is released on every disconnect
		// path (success, error, panic, timeout) without threading an
		// explicit release through every error branch.
		if let Some(counter) = &self.per_account_counter
			&& let Some(peer) = self.peer_ip
		{
			match counter.try_acquire(&account, peer) {
				Ok(slot) => self.per_account_slot = Some(slot),
				Err(_) => {
					return Output::text(format!(
						"{tag} NO [LIMIT] Too many concurrent connections for this account\r\n"
					));
				}
			}
		}
		self.state = State::Authenticated { account };
		Output::text(format!("{tag} OK {completion}\r\n"))
	}
}
