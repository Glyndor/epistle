//! IMAP network layer: implicit TLS only.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[allow(unused_imports)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::smtp::line::{LineDecoder, LineError};

use super::session::Session;
use crate::net::conn_limit::Refusal;
use crate::net::deadline::{DEFAULT_PREAUTH_TIMEOUT, SessionClock};
use crate::net::response_writer;
use server_literal::{Taken, take_exact};

/// How a listener negotiates TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
	/// TLS handshake before any IMAP traffic (`imaps`, 993).
	Implicit,
	/// Plaintext greeting; STARTTLS upgrade required before LOGIN (`imap`, 143).
	StartTls,
}

/// Maximum concurrent IMAP connections per listener.
const MAX_CONNECTIONS: usize = 500;

/// Idle read timeout. RFC 9051 §5.4 recommends the server close the connection
/// after 30 minutes of inactivity; we enforce it to kill Slowloris sessions.
pub(crate) const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(1800);

/// What a session gets when the server drains.
const SHUTTING_DOWN: &[u8] = b"* BYE server shutting down\r\n";

/// How often to poll for new messages during IDLE.
const IDLE_POLL: Duration = Duration::from_secs(30);

/// Consecutive `BAD` responses before the connection is dropped (abuse guard).
pub(crate) const MAX_ERROR_STREAK: u32 = 20;

/// What a connection over a cap is told before it is closed.
fn refusal(why: Refusal) -> &'static [u8] {
	match why {
		Refusal::ListenerFull => b"* BYE too many connections, try again later\r\n",
		Refusal::ClientFull => b"* BYE too many connections from your address\r\n",
	}
}

/// Whether a server response is a `BAD` protocol error (abuse signal).
fn is_bad_response(bytes: &[u8]) -> bool {
	bytes.windows(5).any(|window| window == b" BAD ")
}

/// Anything the connection loop can read from and write to.
trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

/// IMAP server: one instance per listener.
pub struct Server {
	hostname: String,
	data_dir: PathBuf,
	directory: DirectoryHandle,
	tls: TlsAcceptor,
	tls_mode: TlsMode,
	quota_bytes: u64,
	oauth: Option<Arc<crate::oauth::OauthVerifier>>,
	/// `tls-server-end-point` hash; enables AUTH=SCRAM-SHA-256-PLUS.
	cbind_data: Option<crate::tls::EndPoint>,
	/// Whether SCRAM-SHA-256 / SCRAM-SHA-256-PLUS are offered on this
	/// listener (the `[auth] scram` knob). `true` keeps the historical
	/// behaviour; `false` hides both mechanisms in `CAPABILITY AUTH=` and
	/// refuses an explicit `AUTHENTICATE` against them. PLAIN/LOGIN stay in.
	scram_enabled: bool,
	/// Max concurrent connections for this listener (back-pressure cap).
	max_connections: usize,
	/// Max concurrent connections one client may hold on this listener.
	max_per_ip: usize,
	/// At-rest crypto for stored message bodies, shared by every session.
	crypto: crate::storage::MessageCrypto,
	/// Idle / command read timeout: how long a single read (including the
	/// literal read for APPEND/REPLACE) may stall before the connection is
	/// dropped. Configurable so tests can drive a short deadline.
	read_timeout: Duration,
	/// Deadline for the whole phase before authentication, counted from the
	/// start of the connection. Never longer than `read_timeout`.
	preauth_timeout: Duration,
	/// The graceful stop this listener follows.
	drain: Option<Arc<crate::shutdown::Drain>>,
	/// Days to keep expunged messages in `<account>/.archive/` before the
	/// hourly sweeper removes them. `0` keeps the legacy behaviour:
	/// expunge deletes the on-disk files immediately. The sweep itself runs
	/// in [`crate::cli::serve::tasks::sweeps::spawn_archive_sweep`].
	retention_days: u64,
	/// The authentication protocol this listener serves (`Imap` or
	/// `Imaps`); tagged on every password attempt through this server so a
	/// per-account `allowed_protocols` set can admit or reject it. Default
	/// `Protocol::Imaps` matches the historical behaviour.
	auth_protocol: crate::config::Protocol,
	/// The bounded queue to the per-account Bayesian trainer, handed to
	/// every session. `None` disables training and STORE answers the same.
	training: Option<crate::antispam::training_queue::TrainingQueue>,
	/// APPENDLIMIT (RFC 7889): the largest literal an APPEND or REPLACE
	/// command may carry. Follows `[server] max_message_size`, the same
	/// cap the SMTP, REST and JMAP submission paths enforce. Default is
	/// [`super::command::DEFAULT_APPEND_LIMIT`].
	append_limit: usize,
	/// Shared per-account counter applied after authentication. A
	/// session over the cap answers `NO [LIMIT]` and closes; the slot
	/// is released on every disconnect path.
	per_account_counter: Option<Arc<crate::net::per_account_conn::PerAccountCounter>>,
}

impl Server {
	/// Create a server. TLS material is mandatory either way: LOGIN never
	/// crosses plaintext.
	pub fn new(
		hostname: &str,
		data_dir: PathBuf,
		directory: DirectoryHandle,
		tls: TlsAcceptor,
		tls_mode: TlsMode,
	) -> Self {
		Server {
			hostname: hostname.to_string(),
			data_dir,
			directory,
			tls,
			tls_mode,
			quota_bytes: super::session::DEFAULT_QUOTA_BYTES,
			oauth: None,
			cbind_data: None,
			scram_enabled: true,
			max_connections: MAX_CONNECTIONS,
			max_per_ip: crate::net::conn_limit::DEFAULT_MAILBOX_CONNECTIONS_PER_IP,
			crypto: crate::storage::MessageCrypto::disabled(),
			read_timeout: DEFAULT_READ_TIMEOUT,
			preauth_timeout: DEFAULT_PREAUTH_TIMEOUT,
			drain: None,
			retention_days: 0,
			auth_protocol: crate::config::Protocol::Imaps,
			training: None,
			append_limit: super::command::DEFAULT_APPEND_LIMIT,
			per_account_counter: None,
		}
	}

	/// Drive one connection: TLS handshake (or plaintext with STARTTLS),
	/// then the command loop. `peer` is the client IP, used to enforce
	/// app-password CIDR allowlists; `None` for in-memory tests.
	pub async fn handle<S>(&self, stream: S, peer: Option<std::net::IpAddr>) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let mut clock = SessionClock::start(self.preauth_timeout, self.read_timeout);
		let (mut stream, mut session): (Box<dyn Connection>, Session) = match self.tls_mode {
			TlsMode::Implicit => {
				let tls =
					crate::tls::accept_until(&self.tls, stream, clock.preauth_until()).await?;
				let identity = tls
					.get_ref()
					.1
					.peer_certificates()
					.and_then(|certs| certs.first())
					.and_then(|cert| crate::tls::identity_from_cert(cert.as_ref()));
				let mut session = self.new_session();
				session.set_client_identity(identity);
				(Box::new(tls), session)
			}
			TlsMode::StartTls => (Box::new(stream), self.new_session().with_starttls()),
		};
		session.set_peer_ip(peer);

		let greeting = session.greeting();
		response_writer::write_response(&mut *stream, &greeting.bytes, &clock, false).await?;

		let mut decoder = LineDecoder::with_limit(super::command::MAX_COMMAND_LINE);
		let mut buffer = [0u8; 4096];
		// Consecutive BAD responses; too many means an abusive client.
		let mut error_streak = 0u32;
		// Set after a rejected literal is drained: the next line is the rest
		// of that command, not a new one.
		let mut rejected_tail = false;
		// The total budget of the command whose literal was rejected. It is
		// fixed when the rejection is seen and not moved by the
		// continuations that follow, so a chain of rejected literals
		// cannot extend the session the way a chain of commands does.
		let mut rejected_until: Option<Instant> = None;
		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => {
					clock.line_done();
					line
				}
				Ok(None) => {
					// With NOTIFY active (RFC 5465), poll the selected mailbox at
					// IDLE_POLL intervals while waiting for the next command and
					// push unsolicited EXISTS/EXPUNGE, bounded by the line's
					// deadline: absolute, so trickled bytes do not move it.
					// A line that belongs to a rejected command shares the
					// budget of that command, so its continuations cannot
					// push the deadline out.
					let line_deadline = clock.line(session.is_authenticated());
					let deadline = match rejected_until {
						Some(until) => std::cmp::min(line_deadline, until),
						None => line_deadline,
					};
					let read = loop {
						let remaining = deadline.saturating_duration_since(Instant::now());
						let poll = if session.notify_active() {
							IDLE_POLL.min(remaining)
						} else {
							remaining
						};
						let reading = stream.read(&mut buffer);
						let Some(waited) =
							crate::shutdown::or_drain(self.drain.as_deref(), poll, reading).await
						else {
							let _ = response_writer::write_response(
								&mut *stream,
								SHUTTING_DOWN,
								&clock,
								session.is_authenticated(),
							)
							.await;
							return Ok(());
						};
						match waited {
							Ok(Ok(n)) => break n,
							Ok(Err(e)) => return Err(e),
							Err(_) => {
								if !session.notify_active() || Instant::now() >= deadline {
									tracing::debug!("IMAP idle timeout, closing connection");
									let _ = response_writer::write_response(
										&mut *stream,
										b"* BYE idle timeout\r\n",
										&clock,
										session.is_authenticated(),
									)
									.await;
									return Ok(());
								}
								if let Some(notification) = session.check_notify()
									&& response_writer::write_response(
										&mut *stream,
										&notification.bytes,
										&clock,
										session.is_authenticated(),
									)
									.await
									.is_err()
								{
									return Ok(());
								}
							}
						}
					};
					if read == 0 {
						return Ok(());
					}
					decoder.feed(&buffer[..read]);
					continue;
				}
				Err(error) => {
					let message: &[u8] = match error {
						LineError::TooLong => b"* BYE line too long\r\n",
						LineError::BareControlCharacter | LineError::NulByte => {
							b"* BYE protocol error\r\n"
						}
					};
					response_writer::write_response(
						&mut *stream,
						message,
						&clock,
						session.is_authenticated(),
					)
					.await?;
					return Ok(());
				}
			};

			if rejected_tail {
				// What follows a drained literal belongs to the rejected
				// command (its CRLF, a UTF8 item's `)`, a MULTIAPPEND's next
				// message), not to a new one.
				let deadline =
					*rejected_until.get_or_insert_with(|| clock.step(session.is_authenticated()));
				match discard::rejected_tail(
					&mut *stream,
					&mut decoder,
					&line,
					deadline,
					self.append_limit,
				)
				.await?
				{
					Some(more) => {
						rejected_tail = more;
						if !more {
							// The command is over: the next one gets a
							// budget of its own.
							rejected_until = None;
						}
					}
					None => return Ok(()),
				}
				continue;
			}

			let Ok(line) = String::from_utf8(line) else {
				response_writer::write_response(
					&mut *stream,
					b"* BAD non-ASCII command\r\n",
					&clock,
					session.is_authenticated(),
				)
				.await?;
				error_streak += 1;
				if error_streak >= MAX_ERROR_STREAK {
					let _ = response_writer::write_response(
						&mut *stream,
						b"* BYE too many errors\r\n",
						&clock,
						session.is_authenticated(),
					)
					.await;
					return Ok(());
				}
				continue;
			};

			if discard::oversized_sent_literal(&line, self.append_limit) {
				response_writer::write_response(
					&mut *stream,
					b"* BYE literal too large\r\n",
					&clock,
					session.is_authenticated(),
				)
				.await?;
				return Ok(());
			}

			let mut output = session.command_line(&line);
			// Abuse guard: drop a client that only produces BAD responses.
			if is_bad_response(&output.bytes) {
				error_streak += 1;
				if error_streak >= MAX_ERROR_STREAK {
					let _ = response_writer::write_response(
						&mut *stream,
						b"* BYE too many errors\r\n",
						&clock,
						session.is_authenticated(),
					)
					.await;
					return Ok(());
				}
			} else {
				error_streak = 0;
			}
			loop {
				response_writer::write_response(
					&mut *stream,
					&output.bytes,
					&clock,
					session.is_authenticated(),
				)
				.await?;
				if output.close {
					return Ok(());
				}
				if let Some(size) = output.discard_literal {
					// RFC 7888 §4: a non-synchronizing literal whose command
					// was rejected still has its payload on the wire. Drain
					// exactly `size` bytes so they never arrive as the next
					// command, and drop the rest of the command's line
					// (`rejected_tail`). The rejection has already been
					// written; return to the command loop.
					// The whole command shares one budget, fixed here, so a
					// chain of rejected continuations cannot extend it.
					let deadline = *rejected_until
						.get_or_insert_with(|| clock.step(session.is_authenticated()));
					if !discard::literal_or_close(&mut *stream, &mut decoder, size, deadline)
						.await?
					{
						return Ok(());
					}
					rejected_tail = true;
					break;
				}
				if let Some(size) = output.collect_literal {
					// Read exactly `size` literal bytes, then verify the
					// next two octets are CRLF (RFC 9051 §6.3.2). Without
					// the trailer check the message is appended before the
					// client has shown it understood the framing, and a
					// malicious peer can store an unwanted message by
					// sending any two non-CRLF bytes after the literal.
					// Both reads are bounded by the same idle/command
					// deadline as any other read.
					let deadline = clock.step(session.is_authenticated());
					let literal =
						match take_exact(&mut *stream, &mut decoder, size, deadline).await? {
							Taken::Done(bytes) => bytes,
							Taken::Closed => return Ok(()),
							Taken::TimedOut => {
								tracing::debug!("IMAP literal read timeout, closing");
								let _ = response_writer::write_response(
									&mut *stream,
									b"* BYE read timeout\r\n",
									&clock,
									session.is_authenticated(),
								)
								.await;
								return Ok(());
							}
						};
					// Now consume exactly the trailer (CRLF, or `)` CRLF after
					// a UTF8 APPEND literal). The decoder keeps any surplus
					// for the next command line.
					let expected = output.literal_trailer;
					let trailer =
						match take_exact(&mut *stream, &mut decoder, expected.len(), deadline)
							.await?
						{
							Taken::Done(bytes) => bytes,
							Taken::Closed => return Ok(()),
							Taken::TimedOut => {
								tracing::debug!("IMAP literal trailer timeout, closing");
								let _ = response_writer::write_response(
									&mut *stream,
									b"* BYE read timeout\r\n",
									&clock,
									session.is_authenticated(),
								)
								.await;
								return Ok(());
							}
						};
					if trailer == expected {
						output = session.literal_done(&literal);
					} else {
						// Put the non-CRLF trailer bytes back into the
						// decoder so the next command line sees them; the
						// session rejects without storing the message.
						decoder.feed(&trailer);
						output = session.literal_bad_trailer();
					}
					continue;
				}
				if output.collect_auth {
					// Read one SASL continuation line and feed it back.
					let deadline = clock.step(session.is_authenticated());
					let response = loop {
						match decoder.next_line() {
							Ok(Some(line)) => break line,
							Ok(None) => {
								let read = match tokio::time::timeout_at(
									deadline,
									stream.read(&mut buffer),
								)
								.await
								{
									Ok(Ok(n)) => n,
									Ok(Err(e)) => return Err(e),
									Err(_) => return Ok(()),
								};
								if read == 0 {
									return Ok(());
								}
								decoder.feed(&buffer[..read]);
							}
							Err(_) => return Ok(()),
						}
					};
					let response = String::from_utf8(response).unwrap_or_default();
					output = session.auth_response(&response);
					continue;
				}
				if output.compress {
					// RFC 4978 §3: the tagged OK travels uncompressed, and
					// everything after it is deflated. The write and flush
					// above have already put it on the wire in the clear, so
					// wrapping here is the first byte of the compressed
					// stream. The line decoder keeps its state, but anything
					// it already holds arrived in the clear behind the
					// COMPRESS line: a client waits for the OK before it
					// deflates, so a surplus is a forged command that must
					// not run as plaintext after the switch.
					if decoder.discard_buffered(usize::MAX) > 0 {
						return Ok(());
					}
					stream = Box::new(super::compress::Deflate::new(stream));
					// break, not continue: this inner loop re-reads the same
					// `output`, whose `compress` flag is still set, so
					// continuing here would wrap the stream forever.
					break;
				}
				if output.upgrade_tls {
					// Pre-handshake bytes are dropped: nothing buffered in
					// plaintext can leak into the TLS session.
					let tls =
						crate::tls::accept_until(&self.tls, stream, clock.preauth_until()).await?;
					// A verified client certificate enables SASL EXTERNAL.
					let identity = tls
						.get_ref()
						.1
						.peer_certificates()
						.and_then(|certs| certs.first())
						.and_then(|cert| crate::tls::identity_from_cert(cert.as_ref()));
					session.set_client_identity(identity);
					stream = Box::new(tls);
					session.tls_started();
					decoder = LineDecoder::with_limit(super::command::MAX_COMMAND_LINE);
					break;
				}
				if output.idle {
					match self
						.wait_idle(
							&mut *stream,
							&mut decoder,
							&mut buffer,
							&clock,
							&mut session,
						)
						.await?
					{
						idle::Outcome::Done => {}
						idle::Outcome::Closed => return Ok(()),
					}
					output = session.idle_done();
					continue;
				}
				break;
			}
		}
	}
}

mod builder;

#[cfg(test)]
mod tests;

mod accept;

mod discard;

mod idle;

mod server_literal;

mod session_factory;
