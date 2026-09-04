//! Policy decisions on top of the raw delivery: admin-configured external
//! forwarding, and the account's Sieve filter. Pulled out of `delivery.rs`
//! so the parent's policy-free plumbing (the storage layout, the mailbox
//! naming check, the report-ingest hook) is the readable surface.

use std::fs;

use crate::smtp::session::AcceptedMessage;
use crate::storage::delivery::{LocalDelivery, MAX_FORWARD_HOPS, received_hops};

impl LocalDelivery {
	/// Admin-configured external forwarding targets for an account, with the
	/// keep-local flag. Empty when the account has no forwarding, the sender
	/// is null (a bounce, never forward, loop risk), or the message has
	/// already traversed too many hops (loop guard).
	pub(super) fn account_forwards(
		&self,
		account: &str,
		message: &AcceptedMessage,
	) -> (Vec<String>, bool) {
		let directory = self.directory.current();
		let Some((targets, keep_local)) = directory.forwards(account) else {
			return (Vec::new(), true);
		};
		if message.reverse_path.is_empty() || received_hops(&message.data) > MAX_FORWARD_HOPS {
			return (Vec::new(), keep_local);
		}
		(targets.to_vec(), keep_local)
	}

	/// Evaluate the account's Sieve filter, if present and valid. Any read,
	/// lex or parse failure yields `None` so delivery falls back to INBOX
	/// rather than dropping mail.
	pub(super) fn sieve_outcome(
		&self,
		account: &str,
		message: &AcceptedMessage,
	) -> Option<crate::sieve::interp::Outcome> {
		let path = self.accounts_root.join(account).join("filter.sieve");
		let source = fs::read_to_string(path).ok()?;
		let tokens = crate::sieve::lexer::tokenize(&source).ok()?;
		let commands = crate::sieve::parser::parse(&tokens).ok()?;
		let parsed = crate::sieve::interp::Message::parse(&message.data)
			.with_envelope(message.reverse_path.clone(), message.recipients.clone());
		Some(crate::sieve::interp::evaluate(&commands, &parsed))
	}
}