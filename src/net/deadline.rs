//! The clock of one mail-protocol session (IMAP, POP3).
//!
//! A timeout on each read is not a bound: a client that sends one byte just
//! before it fires keeps the connection for as long as it likes. Before
//! authentication the whole phase therefore shares one deadline counted from
//! the start of the session, and neither the bytes that arrive nor a stream
//! of cheap commands move it. Afterwards a command gets the idle timeout for
//! its line from the moment the server starts waiting for it, and a fresh one
//! for every later step of that command (a literal, a SASL line).

use std::time::Duration;

use tokio::time::Instant;

/// How long a client gets, from the start of the connection, to sign in: the
/// handshake, every command and every literal before it count against this
/// one deadline. A signed-in session gets the idle timeout of its protocol.
pub const DEFAULT_PREAUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// The deadlines of one session.
pub struct SessionClock {
	preauth_until: Instant,
	idle: Duration,
	line: Option<Instant>,
}

impl SessionClock {
	/// Start the clock now. The pre-authentication phase never outlasts one
	/// idle timeout, whatever `preauth` says.
	pub fn start(preauth: Duration, idle: Duration) -> Self {
		SessionClock {
			preauth_until: Instant::now() + preauth.min(idle),
			idle,
			line: None,
		}
	}

	/// The end of the pre-authentication phase.
	pub fn preauth_until(&self) -> Instant {
		self.preauth_until
	}

	/// The deadline for a step that begins now: the end of the
	/// pre-authentication phase, or a full idle timeout once signed in.
	pub fn step(&self, authenticated: bool) -> Instant {
		if authenticated {
			Instant::now() + self.idle
		} else {
			self.preauth_until
		}
	}

	/// The deadline for the command line being waited for. It is fixed by
	/// the first call and stays put through partial reads until
	/// [`Self::line_done`], so a trickle of bytes does not move it.
	pub fn line(&mut self, authenticated: bool) -> Instant {
		let deadline = self.step(authenticated);
		*self.line.get_or_insert(deadline)
	}

	/// A complete line arrived: the next wait gets a deadline of its own.
	pub fn line_done(&mut self) {
		self.line = None;
	}
}

#[cfg(test)]
#[path = "deadline_tests.rs"]
mod tests;
