//! The limit on commands that bring a session no closer to a delivered
//! message. Outside a transaction a connection costs a slot of the listener
//! and of its client's address, and NOOP, RSET, VRFY, a refused command or
//! an AUTH response line every few minutes kept it for ever. Past the limit the
//! client is answered `421 4.7.0` and the connection is closed.
//!
//! Two counts share the limit, as Postfix keeps its junk count apart from
//! its error count. Commands that never move a message (NOOP, RSET, VRFY,
//! unknown verbs such as EXPN, HELP or ETRN, a greeting after the one each
//! connection and each TLS start need, an empty BDAT chunk that is not the
//! last, an AUTH response line) count for the whole session: a delivered
//! message or a login does not reset them, and a logged-in client has the
//! same limit. Refused commands (syntax errors, refused MAIL and RCPT,
//! commands out of sequence) count only since the last message the server
//! accepted: a relay delivering a list with many recipients that no longer
//! exist keeps its connection as long as its messages go through, while a
//! client that only collects refusals is a scanner and is cut.

use super::types::State;
use super::{Action, Reply, Session};
use crate::smtp::command::{Command, ParseError};

/// Commands without progress one session may send before it is closed:
/// the same default as Postfix's `smtpd_junk_command_limit`.
pub const DEFAULT_JUNK_COMMAND_LIMIT: u32 = 100;

/// The two counts of one session and the limit they share.
#[derive(Debug)]
pub(super) struct JunkCount {
	/// `0` turns both counts off.
	limit: u32,
	/// Commands without progress, for the whole session.
	junk: u32,
	/// Refused commands since the last accepted message.
	refused: u32,
}

impl Default for JunkCount {
	fn default() -> Self {
		JunkCount {
			limit: DEFAULT_JUNK_COMMAND_LIMIT,
			junk: 0,
			refused: 0,
		}
	}
}

impl JunkCount {
	/// Count one step; `true` once either count is past the limit.
	fn count(&mut self, junk: bool, refused: bool) -> bool {
		if self.limit == 0 {
			return false;
		}
		if junk {
			self.junk = self.junk.saturating_add(1);
		} else if refused {
			self.refused = self.refused.saturating_add(1);
		} else {
			return false;
		}
		self.junk > self.limit || self.refused > self.limit
	}
}

impl Session {
	/// Close the session after `limit` commands without progress, or
	/// `limit` refusals since its last accepted message; `0` turns the
	/// limit off.
	pub fn with_junk_command_limit(mut self, limit: u32) -> Self {
		self.junk.limit = limit;
		self
	}

	/// The server accepted the message this session sent (after every
	/// check on its body, not only the session's own): the refusals that
	/// came before it were part of a real delivery and are forgiven.
	pub fn message_delivered(&mut self) {
		self.junk.refused = 0;
	}

	/// Refuse a command line that is not UTF-8 as the syntax error it is,
	/// and count it like one.
	pub fn unreadable_command(&mut self) -> Action {
		self.count_junk(false, Action::Continue(Reply::syntax_error()))
	}

	/// Whether `parsed` is a command that never moves a message forward,
	/// whatever its reply.
	pub(super) fn is_junk(&self, parsed: &Result<Command, ParseError>) -> bool {
		match parsed {
			Ok(Command::Noop | Command::Rset | Command::Vrfy) => true,
			// One greeting is needed after the banner and one after STARTTLS
			// (which puts the session back to `Connected`); any other is junk.
			Ok(Command::Helo { .. } | Command::Ehlo { .. }) => self.state != State::Connected,
			Ok(Command::Bdat {
				size: 0,
				last: false,
			})
			| Err(ParseError::UnknownCommand) => true,
			_ => false,
		}
	}

	/// Count the step that produced `action` when it brought the session no
	/// closer to a message: a `junk` step (see [`Self::is_junk`], and every
	/// AUTH response line) whatever its reply, or a refusal. Past the limit
	/// the transaction is dropped and the session ends with `421 4.7.0`.
	pub(super) fn count_junk(&mut self, junk: bool, action: Action) -> Action {
		let refused = match &action {
			Action::Continue(reply) | Action::DiscardChunk { reply, .. } => reply.code() >= 400,
			_ => false,
		};
		if !self.junk.count(junk, refused) {
			return action;
		}
		if let Some(metrics) = &self.metrics {
			metrics.abuse_dropped();
		}
		tracing::info!("closing a client after too many commands without progress");
		self.reset();
		Action::Close(Reply::single(
			421,
			"4.7.0 too many commands without progress, closing connection",
		))
	}
}
