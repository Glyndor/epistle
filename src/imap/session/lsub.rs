//! IMAP SUBSCRIBE / UNSUBSCRIBE / LSUB (RFC 9051 §6.3.6).

use super::{Output, Session, mailbox};

impl Session {
	pub(super) fn lsub(&mut self, tag: &str, pattern: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let mut response = String::new();
		for name in mailbox::list_subscribed(&self.data_dir, &account) {
			let matches = pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case(&name);
			if matches {
				response.push_str(&format!("* LSUB () \"/\" \"{name}\"\r\n"));
			}
		}
		response.push_str(&format!("{tag} OK LSUB completed\r\n"));
		Output::text(response)
	}

	pub(super) fn subscription_op(
		&mut self,
		tag: &str,
		operation: impl FnOnce(&std::path::Path, &str) -> std::io::Result<()>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match operation(&self.data_dir, &account) {
			Ok(()) => Output::text(format!("{tag} OK completed\r\n")),
			Err(error) => Output::text(format!("{tag} NO {error}\r\n")),
		}
	}
}
