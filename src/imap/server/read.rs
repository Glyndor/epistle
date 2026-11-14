//! The two waits of the connection loop that read from the socket: for the
//! next bytes of a command, and for the next line of a SASL exchange. Split
//! from `mod.rs`.

use super::*;

impl Server {
	/// Wait until `deadline` for more bytes from the client and read them
	/// into `buffer`.
	///
	/// With NOTIFY active (RFC 5465), poll the selected mailbox at
	/// `IDLE_POLL` intervals while waiting and push unsolicited
	/// EXISTS/EXPUNGE. Returns the number of bytes read, or `None` when the
	/// connection must end: the server is draining, the deadline passed, a
	/// poll found the account disabled or reset, or a notification could not
	/// be written.
	pub(super) async fn read_more<S>(
		&self,
		stream: &mut S,
		buffer: &mut [u8],
		clock: &SessionClock,
		session: &mut Session,
		deadline: Instant,
	) -> std::io::Result<Option<usize>>
	where
		S: AsyncRead + AsyncWrite + Unpin + ?Sized,
	{
		loop {
			let remaining = deadline.saturating_duration_since(Instant::now());
			let poll = if session.notify_active() {
				IDLE_POLL.min(remaining)
			} else {
				remaining
			};
			let reading = stream.read(buffer);
			let Some(waited) =
				crate::shutdown::or_drain(self.drain.as_deref(), poll, reading).await
			else {
				let _ = response_writer::write_response(
					stream,
					SHUTTING_DOWN,
					clock,
					session.is_authenticated(),
				)
				.await;
				return Ok(None);
			};
			match waited {
				Ok(Ok(n)) => return Ok(Some(n)),
				Ok(Err(e)) => return Err(e),
				Err(_) => {
					if !session.notify_active() || Instant::now() >= deadline {
						tracing::debug!("IMAP idle timeout, closing connection");
						let _ = response_writer::write_response(
							stream,
							b"* BYE idle timeout\r\n",
							clock,
							session.is_authenticated(),
						)
						.await;
						return Ok(None);
					}
					if self.end_if_withdrawn(stream, clock, session).await {
						return Ok(None);
					}
					if let Some(notification) = session.check_notify()
						&& response_writer::write_response(
							stream,
							&notification.bytes,
							clock,
							session.is_authenticated(),
						)
						.await
						.is_err()
					{
						return Ok(None);
					}
				}
			}
		}
	}
}

/// Read one SASL continuation line, bounded by `deadline`. `None` when the
/// connection ends first: closed, timed out, or a malformed line.
pub(super) async fn read_auth_line<S>(
	stream: &mut S,
	decoder: &mut LineDecoder,
	buffer: &mut [u8],
	deadline: Instant,
) -> std::io::Result<Option<Vec<u8>>>
where
	S: AsyncRead + Unpin + ?Sized,
{
	loop {
		match decoder.next_line() {
			Ok(Some(line)) => return Ok(Some(line)),
			Ok(None) => {
				let read = match tokio::time::timeout_at(deadline, stream.read(buffer)).await {
					Ok(Ok(n)) => n,
					Ok(Err(e)) => return Err(e),
					Err(_) => return Ok(None),
				};
				if read == 0 {
					return Ok(None);
				}
				decoder.feed(&buffer[..read]);
			}
			Err(_) => return Ok(None),
		}
	}
}
