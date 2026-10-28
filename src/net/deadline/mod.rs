//! The clock of one mail-protocol session (IMAP, POP3, ManageSieve).
//!
//! A timeout on each read is not a bound: a client that sends one byte just
//! before it fires keeps the connection for as long as it likes. Before
//! authentication the whole phase therefore shares one deadline counted from
//! the start of the session, and neither the bytes that arrive nor a stream
//! of cheap commands move it. The same bound applies to every byte the server
//! tries to put on the wire before sign-in, so a peer that stops reading
//! cannot fill the output and hold the listener slot past the deadline.
//! Afterwards a command gets the idle timeout for its line from the moment
//! the server starts waiting for it, and a fresh one for every later step
//! of that command (a literal, a SASL line). The response that follows is
//! held to a stall window: the peer has to keep accepting the bytes, and
//! one that stops accepting for longer than the window loses the
//! connection and the listener slot it holds. The window is not a budget
//! for the whole message, so a peer that reads slowly keeps its session.

use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// How long a client gets, from the start of the connection, to sign in: the
/// handshake, every command and every literal before it count against this
/// one deadline. A signed-in session gets the idle timeout of its protocol.
pub const DEFAULT_PREAUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a peer may stop accepting the bytes of a response before the
/// write is given up. The window is refreshed every time bytes go out, so
/// a peer that reads slowly keeps its session and a peer that stopped
/// reading loses it.
pub const DEFAULT_WRITE_STALL: Duration = Duration::from_secs(60);

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

	/// How long a response write may stall before it is given up: the
	/// shorter of the shared stall window and the idle timeout of this
	/// session, so a write is never more patient than the read it waits
	/// for.
	pub fn write_stall(&self) -> Duration {
		DEFAULT_WRITE_STALL.min(self.idle)
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

	/// Open a fresh pre-authentication window of `preauth`, used when
	/// the session signs out (UNAUTHENTICATE) and a new sign-in phase
	/// begins. `preauth` is clamped to one idle timeout, matching
	/// [`Self::start`].
	pub fn restart_preauth_from_now(&mut self, preauth: Duration) {
		self.preauth_until = Instant::now() + preauth.min(self.idle);
		self.line = None;
	}
}

/// Write `message` and flush the stream before `deadline`. Returns
/// `ErrorKind::TimedOut` if the bound passes before both `write_all`
/// and `flush` finish; the underlying [`std::io::Error`] of the stream
/// is otherwise propagated unchanged. The server loops of every
/// pre-authentication protocol call this for the greeting, every
/// response and every error BYE/NO so a peer that stops reading cannot
/// keep the connection alive past the bound.
pub async fn write_all<S>(stream: &mut S, message: &[u8], deadline: Instant) -> std::io::Result<()>
where
	S: AsyncWrite + Unpin + ?Sized,
{
	let write = async {
		stream.write_all(message).await?;
		stream.flush().await
	};
	match tokio::time::timeout_at(deadline, write).await {
		Ok(result) => result,
		Err(_) => Err(std::io::Error::new(
			std::io::ErrorKind::TimedOut,
			"deadline reached while flushing a response",
		)),
	}
}

/// Write `message` and flush the stream. The peer has to keep accepting
/// bytes: it may take `stall` to accept the next one, and a peer that
/// stops accepting for longer is cut with `ErrorKind::TimedOut`. The
/// bound is not a budget for the whole message, so a peer that reads
/// slowly is never cut for being slow, while a peer that stopped reading
/// cannot keep the connection (and its listener slot) past the stall.
pub async fn write_all_progressing<S>(
	stream: &mut S,
	message: &[u8],
	stall: Duration,
) -> std::io::Result<()>
where
	S: AsyncWrite + Unpin + ?Sized,
{
	let mut deadline = Instant::now() + stall;
	let mut written = 0;
	while written < message.len() {
		match tokio::time::timeout_at(deadline, stream.write(&message[written..])).await {
			Ok(Ok(0)) => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::WriteZero,
					"the peer stopped accepting the response",
				));
			}
			Ok(Ok(count)) => {
				written += count;
				deadline = Instant::now() + stall;
			}
			Ok(Err(error)) => return Err(error),
			Err(_) => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::TimedOut,
					"the peer stopped reading the response",
				));
			}
		}
	}
	match tokio::time::timeout_at(deadline, stream.flush()).await {
		Ok(result) => result,
		Err(_) => Err(std::io::Error::new(
			std::io::ErrorKind::TimedOut,
			"the peer stopped reading the response",
		)),
	}
}

#[cfg(test)]
mod tests;
