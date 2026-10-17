//! Policy decisions on top of the raw delivery: admin-configured external
//! forwarding, and the account's Sieve filter. Pulled out of `delivery.rs`
//! so the parent's policy-free plumbing (the storage layout, the mailbox
//! naming check, the report-ingest hook) is the readable surface.

use std::fs;

use crate::smtp::session::AcceptedMessage;
use crate::storage::delivery::{LocalDelivery, MAX_FORWARD_HOPS, received_hops};
use crate::util::path_component::AccountName;

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
		let path = AccountName::new(account)
			.ok()?
			.root(&self.data_dir)
			.and_then(|root| root.file("filter.sieve"))
			.ok()?;
		// The store keeps scripts within its size limit; a file past it was not
		// written by the store, and is not read.
		let size = fs::metadata(&path).ok()?.len();
		if size > crate::managesieve::store::MAX_SCRIPT_BYTES as u64 {
			tracing::warn!(
				account,
				size,
				"the account's Sieve filter is over the size limit; it was not run"
			);
			return None;
		}
		let source = fs::read_to_string(path).ok()?;
		let tokens = crate::sieve::lexer::tokenize(&source).ok()?;
		let commands = crate::sieve::parser::parse(&tokens).ok()?;
		// The `mailbox` extension's `mailboxexists` test consults the
		// account's mailbox list, so hand the interpreter the names in
		// their IMAP on-disk spelling (modified UTF-7). `imap::mailbox::list`
		// always includes INBOX, matching what `mailboxexists "INBOX"`
		// expects.
		let mut mailboxes = crate::imap::mailbox::list(&self.data_dir, account);
		let parsed = crate::sieve::interp::Message::parse(&message.data)
			.with_envelope(message.reverse_path.clone(), message.recipients.clone())
			.with_mailboxes(&mut mailboxes);
		let outcome = crate::sieve::interp::evaluate(&commands, &parsed);
		if outcome.aborted
			&& crate::util::warn_limited::allow(&format!(
				"sieve-aborted:{}:{account}",
				self.data_dir.display()
			)) {
			tracing::warn!(
				account,
				redirects_dropped = outcome.dropped.redirects,
				reject_dropped = outcome.dropped.reject,
				vacation_dropped = outcome.dropped.vacation,
				kept = outcome.keep,
				discarded = outcome.discarded,
				fileinto = outcome.fileinto.len(),
				"the account's Sieve filter used more steps or work than a run may; the run stopped where it was: what it had decided about where the message goes stands, redirects, rejects and vacation replies it had asked for were dropped (and the message kept if any was), and the rest of the script did not run"
			);
		}
		if outcome.inspection_truncated {
			if let Some(metrics) = &self.metrics {
				metrics.sieve_inspection_truncated();
			}
			if crate::util::warn_limited::allow(&format!(
				"sieve-truncated:{}:{account}",
				self.data_dir.display()
			)) {
				tracing::warn!(
					account,
					"a Sieve test of the account's filter looked at part of a message only (the first mebibyte of the body, or the first mebibyte or thousand values of the headers of a lookup); a rule that matches text past that did not see it"
				);
			}
		}
		if outcome.redirects_over_limit > 0
			&& crate::util::warn_limited::allow(&format!(
				"sieve-redirects:{}:{account}",
				self.data_dir.display()
			)) {
			tracing::warn!(
				account,
				ignored = outcome.redirects_over_limit,
				limit = crate::sieve::interp::MAX_REDIRECTS,
				"the account's Sieve filter asked for redirects beyond the limit; they were not forwarded"
			);
		}
		Some(outcome)
	}
}
