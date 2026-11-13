//! The SMTP connection loop: drives one session from greeting to close.

use std::net::IpAddr;

use tokio::io::AsyncReadExt;

use crate::smtp::line::LineDecoder;
use crate::smtp::reply::Reply;
use crate::smtp::session::{Action, Session};
use crate::smtp::trace::line_error_reply;

use super::data_rate::{Cut, RateWindow, send_within};
use super::run_withdrawn::end_withdrawn;
use super::session_time::{SessionClock, end_session};
use super::{
	COMMAND_TIMEOUT, Connection, Mode, READ_BUFFER, Server, discard_chunk, end_cut, read_chunk,
	send,
};

/// Consecutive error replies before the connection is dropped (abuse guard,
/// akin to Postfix's `smtpd_hard_error_limit`).
pub(crate) const MAX_ERROR_STREAK: u32 = 20;

impl Server {
	/// The protocol loop over an established (plain or TLS) stream.
	pub(super) async fn run(
		&self,
		mut stream: Box<dyn Connection>,
		mut session: Session,
		peer: Option<IpAddr>,
	) -> std::io::Result<()> {
		// App-password CIDR allowlists are checked against the peer IP.
		session.set_peer_ip(peer);
		self.metrics.connection();
		send(&mut stream, &session.greeting()).await?;

		let mut decoder = LineDecoder::new();
		let mut mode = Mode::Commands;
		let mut buffer = [0u8; READ_BUFFER];
		// Consecutive error replies; too many means an abusive client.
		let mut error_streak = 0u32;
		// The rate window of the message being received: started at the
		// 354 or at the first BDAT chunk, and kept until the transaction
		// ends, so the time between chunks and the commands sent in it
		// count against the same clock.
		let mut body_window: Option<RateWindow> = None;
		// The lifetime of the session, checked at every command boundary.
		let mut clock = SessionClock::start(self.max_session_time);

		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					// A drain waits for an open transaction, DATA or AUTH to end.
					let idle = mode == Mode::Commands && !session.in_transaction();
					let drain = self.drain.as_deref().filter(|_| idle);
					// A message being received is held to the rate floor.
					let off = RateWindow::off();
					let window = body_window.as_ref().unwrap_or(&off);
					let reading = window.guard(stream.read(&mut buffer));
					let reading = clock.guard(body_window.is_none(), reading);
					let read = match crate::shutdown::or_drain(drain, COMMAND_TIMEOUT, reading)
						.await
					{
						None => {
							send(&mut stream, &Reply::single(421, "4.3.2 shutting down")).await?;
							return Ok(());
						}
						Some(Ok(Some(Some(Ok(n))))) => n,
						Some(Ok(Some(Some(Err(e))))) => return Err(e),
						Some(Ok(Some(None))) => {
							return end_cut(&mut stream, Cut::TooSlow, session).await;
						}
						Some(Ok(None)) => return end_session(&mut stream, session).await,
						Some(Err(_)) => {
							tracing::debug!("SMTP command timeout, closing connection");
							return Ok(());
						}
					};
					if read == 0 {
						return Ok(());
					}
					if mode == Mode::Data
						&& let Some(window) = body_window.as_mut()
					{
						window.record(read);
					}
					decoder.feed(&buffer[..read]);
					continue;
				}
				Err(error) => {
					send(&mut stream, &line_error_reply(&error)).await?;
					return Ok(());
				}
			};

			// A command or AUTH line past the session's lifetime is not run
			// (QUIT still is: the client is leaving); a message body being
			// received is left to finish.
			if mode != Mode::Data
				&& body_window.is_none()
				&& clock.expired()
				&& !line.eq_ignore_ascii_case(b"QUIT")
			{
				return end_session(&mut stream, session).await;
			}
			// In Data mode, pass raw bytes to support 8BITMIME (RFC 6152).
			let action = 'line: {
				if mode == Mode::Data {
					break 'line session.data_line(&line);
				}
				let Ok(line_str) = String::from_utf8(line) else {
					// A command that is not UTF-8 is refused and counted like
					// any syntax error.
					if mode == Mode::Commands {
						break 'line Some(session.unreadable_command());
					}
					// Auth responses must be ASCII; abort.
					send(
						&mut stream,
						&Reply::single(501, "5.5.2 non-ASCII in AUTH response"),
					)
					.await?;
					return Ok(());
				};
				// Each command and AUTH round uses the latest published account rules.
				session = session.with_directory(self.directory.current());
				if self.account_withdrawn(&session) {
					return end_withdrawn(&mut stream, session).await;
				}
				match mode {
					Mode::Commands => Some(session.command_line(&line_str)),
					// Argon2 is CPU-bound; per-connection rate limiting keeps attempts scarce.
					Mode::Auth => Some(session.auth_line(&line_str)),
					Mode::Data => unreachable!(),
				}
			};
			let Some(mut action) = action else {
				continue;
			};

			mode = Mode::Commands;
			// Resolve BDAT chunk reads (RFC 3030) into a terminal action that the
			// dispatch below already handles (Continue for a non-final chunk,
			// Deliver for the LAST chunk — so the full delivery path still runs).
			let action = loop {
				action = match action {
					// The first chunk starts the window of the transaction.
					Action::CollectChunk { size, last } => {
						let window = body_window.get_or_insert_with(|| self.message_window());
						let read = (size, last);
						match read_chunk(&mut stream, &mut decoder, read, window, &mut session)
							.await?
						{
							Ok(action) => action,
							Err(cut) => return end_cut(&mut stream, cut, session).await,
						}
					}
					// A refused chunk is consumed without being kept.
					Action::DiscardChunk { size, reply } => {
						let window = body_window.get_or_insert_with(|| self.message_window());
						if let Err(cut) =
							discard_chunk(&mut stream, &mut decoder, size, window).await?
						{
							return end_cut(&mut stream, cut, session).await;
						}
						Action::Continue(reply)
					}
					resolved => break resolved,
				};
			};
			// The window ends with the transaction: the dot, the LAST
			// chunk, RSET, or any refusal that resets it.
			if !session.in_transaction() && body_window.take().is_some() {
				clock.body_ended();
			}
			match action {
				Action::Continue(reply) => {
					// Abuse guard: disconnect a client that only produces errors.
					if reply.code() >= 400 {
						error_streak += 1;
						if error_streak >= MAX_ERROR_STREAK {
							self.metrics.abuse_dropped();
							send(
								&mut stream,
								&Reply::single(421, "4.7.0 too many errors, closing connection"),
							)
							.await?;
							return Ok(());
						}
					} else {
						error_streak = 0;
					}
					// Inside a transaction an unread reply counts as idle time.
					if !send_within(&mut stream, &reply, body_window.as_ref()).await? {
						return Ok(());
					}
				}
				Action::CollectData(reply) => {
					mode = Mode::Data;
					send(&mut stream, &reply).await?;
					body_window = Some(self.message_window());
				}
				// BDAT chunk reads are resolved into a terminal action above.
				Action::CollectChunk { .. } | Action::DiscardChunk { .. } => {
					unreachable!("BDAT chunk resolved before dispatch")
				}
				Action::CollectAuthResponse(reply) => {
					mode = Mode::Auth;
					send(&mut stream, &reply).await?;
				}
				// The body arrived without a command boundary to check at.
				Action::Deliver(..) if self.account_withdrawn(&session) => {
					return end_withdrawn(&mut stream, session).await;
				}
				Action::Deliver(reply, message) => {
					self.deliver(&mut stream, &mut session, peer, reply, message)
						.await?;
				}
				Action::UpgradeTls(reply) => {
					let Some(upgraded) = self.upgrade_tls(stream, &mut session, &reply).await?
					else {
						return Ok(());
					};
					stream = upgraded;
					decoder = LineDecoder::new();
				}
				Action::Close(reply) => {
					send(&mut stream, &reply).await?;
					return Ok(());
				}
			}
		}
	}
}
