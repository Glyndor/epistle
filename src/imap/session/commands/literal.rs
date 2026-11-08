//! IMAP literal-bearing command handlers: APPEND (RFC 9051) and REPLACE
//! (RFC 8508). The command line is parsed elsewhere; these begin the
//! literal collection, and [`super::literal_store`] finishes once the
//! payload arrives.

use super::super::mailbox::{self, Flag};
use super::super::state::State;
use super::super::{Output, PendingLiteral, Session};
use crate::imap::internal_date::InternalDate;

/// Build the rejection `Output` for a literal-bearing command. When the
/// command used the non-synchronizing `{n+}` form, the client already sent
/// the payload, so the network layer must consume those bytes (RFC 7888 §4).
fn reject_literal(tag: &str, synchronizing: bool, size: usize, response: &str) -> Output {
	let mut output = Output::text(format!("{tag} {response}"));
	if !synchronizing {
		output.discard_literal = Some(size);
	}
	output
}

/// How the APPEND data was sent: as the RFC 6855 `UTF8 (~{n})` item, or as
/// an RFC 3516 literal8.
pub(in crate::imap::session) struct AppendForm {
	pub(in crate::imap::session) utf8: bool,
	pub(in crate::imap::session) binary: bool,
}

impl Session {
	#[allow(clippy::too_many_arguments)]
	pub(in crate::imap::session) fn append_begin(
		&mut self,
		tag: &str,
		mailbox: &str,
		flag_tokens: &[String],
		date: Option<InternalDate>,
		(size, synchronizing): (usize, bool),
		AppendForm { utf8, binary }: AppendForm,
	) -> Output {
		// A rejected `UTF8 (~{n+})` also drains the `)` after the literal.
		let wire_size = size + usize::from(utf8);
		let Some(account) = self.account().map(str::to_string) else {
			return reject_literal(tag, synchronizing, wire_size, "NO not authenticated\r\n");
		};
		// RFC 6855 §4: the UTF8 data item is only meaningful once enabled.
		if utf8 && !self.utf8_accept {
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"BAD UTF8 APPEND requires ENABLE UTF8=ACCEPT\r\n",
			);
		}
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"NO [TRYCREATE] no such mailbox\r\n",
			);
		}
		// Quota enforcement (RFC 9208): refuse before reading the literal.
		let projected =
			mailbox::account_usage(&self.data_dir, &account, &self.crypto) + size as u64;
		if self
			.effective_quota()
			.is_some_and(|limit| projected > limit)
		{
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"NO [OVERQUOTA] storage quota exceeded\r\n",
			);
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => {
					return reject_literal(
						tag,
						synchronizing,
						wire_size,
						"BAD unsupported flag\r\n",
					);
				}
			}
		}
		// A literal-bearing APPEND can only fail the keyword cap on Set
		// semantics (REPLACE has the same check via the replaced message);
		// refuse here so the client never sends the literal.
		if super::super::mailbox::count_keywords(&flags).is_none() {
			return reject_literal(
				tag,
				synchronizing,
				wire_size,
				"BAD too many keywords (max {})\r\n",
			);
		}
		self.pending_append = Some(PendingLiteral {
			tag: tag.to_string(),
			mailbox: mailbox.to_string(),
			flags,
			date,
			replace: None,
			binary,
		});
		// RFC 7888 §4: a non-synchronizing literal ({n+}) has no
		// continuation response. The client already sent the payload
		// in the same write as the command line, and Dovecot's
		// imaptest (and any IMAP4rev2 client using LITERAL+) crashes
		// when the server replies with `+ ready for literal data`
		// because its APPEND state machine expects the tagged
		// response next.
		let mut output = if synchronizing {
			Output::text("+ ready for literal data\r\n".to_string())
		} else {
			Output::text(String::new())
		};
		output.collect_literal = Some(size);
		if utf8 {
			output.literal_trailer = b")\r\n";
		}
		output
	}

	/// Begin REPLACE (RFC 8508): validate the source message and append target,
	/// then collect the literal. Requires a selected, writable mailbox.
	#[allow(clippy::too_many_arguments)]
	pub(in crate::imap::session) fn replace_begin(
		&mut self,
		tag: &str,
		sequence: u32,
		mailbox: &str,
		flag_tokens: &[String],
		date: Option<InternalDate>,
		size: usize,
		uid: bool,
		synchronizing: bool,
	) -> Output {
		let resolved = {
			let State::Selected {
				snapshot,
				read_only,
				mailbox: selected,
				account,
			} = &self.state
			else {
				return reject_literal(tag, synchronizing, size, "NO no mailbox selected\r\n");
			};
			if *read_only {
				return reject_literal(tag, synchronizing, size, "NO mailbox is read-only\r\n");
			}
			let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
			let target_uid = if uid {
				match (1..=total)
					.find(|n| snapshot.by_sequence(*n).map(|m| m.uid) == Some(sequence))
				{
					Some(seq) => snapshot.by_sequence(seq).map(|m| m.uid).unwrap_or(0),
					None => {
						return reject_literal(tag, synchronizing, size, "NO no such message\r\n");
					}
				}
			} else if sequence >= 1 && sequence <= total {
				snapshot.by_sequence(sequence).map(|m| m.uid).unwrap_or(0)
			} else {
				return reject_literal(tag, synchronizing, size, "NO no such message\r\n");
			};
			if target_uid == 0 {
				return reject_literal(tag, synchronizing, size, "NO no such message\r\n");
			}
			(account.clone(), selected.clone(), target_uid)
		};
		let (account, selected, target_uid) = resolved;

		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return reject_literal(
				tag,
				synchronizing,
				size,
				"NO [TRYCREATE] no such mailbox\r\n",
			);
		}
		let projected =
			mailbox::account_usage(&self.data_dir, &account, &self.crypto) + size as u64;
		if self
			.effective_quota()
			.is_some_and(|limit| projected > limit)
		{
			return reject_literal(
				tag,
				synchronizing,
				size,
				"NO [OVERQUOTA] storage quota exceeded\r\n",
			);
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => {
					return reject_literal(tag, synchronizing, size, "BAD unsupported flag\r\n");
				}
			}
		}
		if super::super::mailbox::count_keywords(&flags).is_none() {
			return reject_literal(
				tag,
				synchronizing,
				size,
				"BAD too many keywords (max {})\r\n",
			);
		}
		self.pending_append = Some(PendingLiteral {
			tag: tag.to_string(),
			mailbox: mailbox.to_string(),
			flags,
			date,
			// Resolve the sequence to a UID at command start: a
			// concurrent session that expunges this message (or any
			// other change to the mailbox) between this point and
			// the literal read must not move the REPLACE target to
			// a different message.
			replace: Some((selected, target_uid)),
			binary: false,
		});
		// See the matching note in `append_begin` above.
		let mut output = if synchronizing {
			Output::text("+ ready for literal data\r\n".to_string())
		} else {
			Output::text(String::new())
		};
		output.collect_literal = Some(size);
		output
	}
}
