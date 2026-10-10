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
		self.state = State::Authenticated { account };
		Output::text(format!("{tag} OK {completion}\r\n"))
	}
}
