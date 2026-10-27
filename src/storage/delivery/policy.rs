//! Policy decisions on top of the raw delivery: admin-configured external
//! forwarding, and the account's Sieve filter. Pulled out of
//! `src/storage/delivery/mod.rs` so the parent's policy-free plumbing (the
//! storage layout, the mailbox naming check, the report-ingest hook) is the
//! readable surface.

use std::fs;

use crate::smtp::session::AcceptedMessage;
use crate::storage::delivery::{LocalDelivery, MAX_FORWARD_HOPS, received_hops};
use crate::util::path_component::AccountName;

impl LocalDelivery {
	/// Whether the line `kind` about `account` may be logged now: once an
	/// hour. A filter that misbehaves does so on every message, and a log
	/// line per message would make the mail itself the way to fill the log.
	pub(super) fn may_say(&self, kind: &str, account: &str) -> bool {
		crate::util::warn_limited::allow(&format!("{kind}:{}:{account}", self.data_dir.display()))
	}

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
			if self.may_say("sieve-size", account) {
				tracing::warn!(
					account,
					size,
					"the account's Sieve filter is over the size limit; it was not run"
				);
			}
			return None;
		}
		let source = fs::read_to_string(path).ok()?;
		let Some(commands) = crate::sieve::lexer::tokenize(&source)
			.ok()
			.and_then(|tokens| crate::sieve::parser::parse(&tokens).ok())
		else {
			// A script stored before a stricter check can be one the parser
			// refuses today (a chain of `not` deeper than 64, say): the mail
			// goes to INBOX, and the owner is told why their filter is idle.
			if self.may_say("sieve-parse", account) {
				tracing::warn!(
					account,
					"the account's Sieve filter could not be read as a Sieve script; it was not run and mail goes to INBOX. Save a corrected script"
				);
			}
			return None;
		};
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
		if outcome.aborted && self.may_say("sieve-aborted", account) {
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
			if self.may_say("sieve-truncated", account) {
				tracing::warn!(
					account,
					"a Sieve test of the account's filter looked at part of a message only (the first mebibyte of the body, the first 10 000 headers, or the first mebibyte or thousand values of the headers of a lookup); a rule that matches text past that did not see it"
				);
			}
		}
		if outcome.pattern_over_caps && self.may_say("sieve-pattern", account) {
			tracing::warn!(
				account,
				max_chars = crate::sieve::MAX_PATTERN_CHARS,
				max_wildcards = crate::sieve::MAX_WILDCARDS,
				"the account's Sieve filter has a :matches key over the length or wildcard limit; its test is false and the rest of the script ran, but from that test on the run keeps the message instead of discarding or rejecting it. Shorten the key"
			);
		}
		if outcome.fileinto_over_limit > 0 && self.may_say("sieve-fileinto", account) {
			tracing::warn!(
				account,
				ignored = outcome.fileinto_over_limit,
				limit = crate::sieve::interp::MAX_FILEINTO,
				"the account's Sieve filter files into folders beyond the limit of folders for one message; those were not carried out"
			);
		}
		if outcome.redirects_over_limit > 0 && self.may_say("sieve-redirects", account) {
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
