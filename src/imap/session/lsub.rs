//! IMAP SUBSCRIBE / UNSUBSCRIBE / LSUB (RFC 9051 §6.3.6).

use super::{Output, Session, mailbox};
use crate::imap::list_tree::{self, Hidden};

impl Session {
	pub(super) fn lsub(&mut self, tag: &str, reference: &str, pattern: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let mut response = String::new();
		let subscriptions = mailbox::list_subscribed(&self.data_dir, &account);
		let matches = |name: &str| crate::imap::list_pattern::matches(reference, pattern, name);
		// RFC 3501 §6.3.9: a level that `%` stops at, and that is not
		// subscribed itself, is returned `\Noselect` for the subscribed
		// names below it.
		for entry in list_tree::select(
			&[],
			&subscriptions,
			|_, _| true,
			matches,
			Hidden::Placeholder,
		) {
			let attributes = if entry.placeholder { "\\Noselect" } else { "" };
			let wire = self.mailbox_astring(entry.name);
			response.push_str(&format!("* LSUB ({attributes}) \"/\" {wire}\r\n"));
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
