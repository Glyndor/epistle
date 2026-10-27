//! The IDLE command: the server waits for DONE and polls the mailbox.
//!
//! While the client idles the server polls the SELECTed mailbox at
//! `IDLE_POLL` intervals and pushes the changes it finds. The wait ends
//! when the client sends DONE, when the connection ends, or when the
//! read timeout of the listener passes, whichever comes first: the poll
//! interval never outlasts the configured timeout.

use super::*;

/// How a wait for DONE ended.
pub(super) enum Outcome {
	/// The client sent DONE: the IDLE is over and the session continues.
	Done,
	/// The connection ends here.
	Closed,
}

impl Server {
	/// Wait for the DONE of an IDLE command, polling the mailbox for
	/// changes while it waits.
	pub(super) async fn wait_idle<S>(
		&self,
		stream: &mut S,
		decoder: &mut LineDecoder,
		buffer: &mut [u8],
		clock: &SessionClock,
		session: &mut Session,
	) -> std::io::Result<Outcome>
	where
		S: AsyncRead + AsyncWrite + Unpin + ?Sized,
	{
		let idle_until = Instant::now() + self.read_timeout;
		loop {
			match decoder.next_line() {
				Ok(Some(line)) => {
					if line.eq_ignore_ascii_case(b"DONE") {
						return Ok(Outcome::Done);
					}
					// Anything else during IDLE is ignored.
					if Instant::now() >= idle_until {
						return Ok(self.close_on_idle_timeout(stream, clock, session).await);
					}
				}
				Ok(None) => {
					let remaining = idle_until.saturating_duration_since(Instant::now());
					if remaining.is_zero() {
						return Ok(self.close_on_idle_timeout(stream, clock, session).await);
					}
					let reading = stream.read(buffer);
					let drain = self.drain.as_deref();
					let Some(waited) =
						crate::shutdown::or_drain(drain, IDLE_POLL.min(remaining), reading).await
					else {
						let _ = response_writer::write_response(
							stream,
							SHUTTING_DOWN,
							clock,
							session.is_authenticated(),
						)
						.await;
						return Ok(Outcome::Closed);
					};
					let read = match waited {
						Ok(Ok(count)) => count,
						Ok(Err(error)) => return Err(error),
						Err(_) => {
							// Poll interval expired; check for new messages.
							if let Some(notification) = session.check_idle()
								&& response_writer::write_response(
									stream,
									&notification.bytes,
									clock,
									session.is_authenticated(),
								)
								.await
								.is_err()
							{
								return Ok(Outcome::Closed);
							}
							continue;
						}
					};
					if read == 0 {
						return Ok(Outcome::Closed);
					}
					decoder.feed(&buffer[..read]);
				}
				Err(_) => return Ok(Outcome::Closed),
			}
		}
	}

	/// Tell the client that its IDLE outlasted the read timeout and end
	/// the session.
	async fn close_on_idle_timeout<S>(
		&self,
		stream: &mut S,
		clock: &SessionClock,
		session: &Session,
	) -> Outcome
	where
		S: AsyncRead + AsyncWrite + Unpin + ?Sized,
	{
		tracing::debug!("IMAP idle timeout during IDLE, closing");
		let _ = response_writer::write_response(
			stream,
			b"* BYE idle timeout\r\n",
			clock,
			session.is_authenticated(),
		)
		.await;
		Outcome::Closed
	}
}
