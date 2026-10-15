//! A lifetime for one SMTP session.
//!
//! The idle timeout bounds each read and the junk-command limit bounds the
//! commands that do nothing, but a client that keeps making a little
//! progress, or drips one command line a byte at a time, could still hold a
//! listener slot and a per-IP slot for hours. Once a session is older than
//! `max_session_time` it is answered `421 4.4.2` and closed at the next
//! command boundary: while it waits for a command, or before it runs one.
//! A message whose body is being received is never cut: the rate floor
//! already bounds it, and it may finish, so the cut comes at the first
//! command after it.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use super::Reply;

/// Default lifetime of one session, in seconds.
pub const DEFAULT_MAX_SESSION_TIME_SECS: u64 = 1800;

/// When the session that started at [`SessionClock::start`] runs out.
#[derive(Debug)]
pub(super) struct SessionClock {
	deadline: Option<Instant>,
	/// When a wait for the next command is cut: the deadline, or a little
	/// later for the command that follows a message whose body was still
	/// arriving when the deadline passed.
	wait_until: Option<Instant>,
}

impl SessionClock {
	/// Start the clock of a session that may last `limit`; a zero `limit`
	/// never runs out.
	pub(super) fn start(limit: Duration) -> Self {
		let deadline = (!limit.is_zero())
			.then(|| Instant::now().checked_add(limit))
			.flatten();
		SessionClock {
			deadline,
			wait_until: deadline,
		}
	}

	/// A message body has just been received. If the session's time ran
	/// out meanwhile, the client still gets one idle timeout to send its
	/// next command (a QUIT is answered; anything else gets the 421)
	/// instead of a close it could not see coming.
	pub(super) fn body_ended(&mut self) {
		if self.expired() {
			self.wait_until = Instant::now().checked_add(super::COMMAND_TIMEOUT);
		}
	}

	/// Whether the session is older than its lifetime.
	pub(super) fn expired(&self) -> bool {
		self.deadline
			.is_some_and(|deadline| Instant::now() >= deadline)
	}

	/// Await `read`, or `None` once the session's time is over. Only a
	/// read that `waits_for_command` is cut: one inside a message body is
	/// left to the rate floor. Bytes already waiting win over a deadline due
	/// at the same moment.
	pub(super) async fn guard<F: Future>(
		&self,
		waits_for_command: bool,
		read: F,
	) -> Option<F::Output> {
		let Some(deadline) = self.wait_until.filter(|_| waits_for_command) else {
			return Some(read.await);
		};
		tokio::select! {
			biased;
			output = read => Some(output),
			() = tokio::time::sleep_until(deadline) => None,
		}
	}
}

/// End a session whose time is over: the session goes first, so what it
/// held is given back even if the client never reads the 421.
pub(super) async fn end_session(
	stream: &mut Box<dyn super::Connection>,
	session: super::Session,
) -> std::io::Result<()> {
	drop(session);
	tracing::info!("closing a client whose session time limit was reached");
	super::send(stream, &time_limit_reached()).await
}

/// What a session gets when its time is over, before the close.
pub(super) fn time_limit_reached() -> Reply {
	Reply::single(421, "4.4.2 session time limit reached")
}
