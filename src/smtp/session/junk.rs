//! The limit on commands that bring a session no closer to a delivered
//! message. Outside a transaction a connection costs a slot of the listener
//! and of its client's address, and NOOP, RSET, VRFY, a refused command or
//! a cancelled AUTH every few minutes kept it for ever. Past the limit the
//! client is answered `421 4.7.0` and the connection is closed. The count
//! covers the whole session: a delivered message does not reset it, and a
//! logged-in client has the same limit.

use super::{Action, Reply, Session};

/// Commands without progress one session may send before it is closed:
/// the same default as Postfix's `smtpd_junk_command_limit`.
pub const DEFAULT_JUNK_COMMAND_LIMIT: u32 = 100;

impl Session {
	/// Close the session after `limit` commands without progress; `0`
	/// turns the limit off.
	pub fn with_junk_command_limit(mut self, limit: u32) -> Self {
		self.junk_command_limit = limit;
		self
	}

	/// Count the step that produced `action` when it brought the session no
	/// closer to a message: a `junk` command (NOOP, RSET, VRFY) whatever its
	/// reply, and every refusal. Past the limit the transaction is dropped
	/// and the session ends with `421 4.7.0`.
	pub(super) fn count_junk(&mut self, junk: bool, action: Action) -> Action {
		let refused = match &action {
			Action::Continue(reply) | Action::DiscardChunk { reply, .. } => reply.code() >= 400,
			_ => false,
		};
		if self.junk_command_limit == 0 || !(junk || refused) {
			return action;
		}
		self.junk_commands = self.junk_commands.saturating_add(1);
		if self.junk_commands <= self.junk_command_limit {
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
