//! IMAP network layer: implicit TLS only.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::smtp::line::{LineDecoder, LineError};

use super::session::Session;

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
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(1800);

/// How often to poll for new messages during IDLE.
const IDLE_POLL: Duration = Duration::from_secs(30);

/// Consecutive `BAD` responses before the connection is dropped (abuse guard).
const MAX_ERROR_STREAK: u32 = 20;

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
	cbind_data: Option<Vec<u8>>,
	/// Max concurrent connections for this listener (back-pressure cap).
	max_connections: usize,
	/// At-rest crypto for stored message bodies, shared by every session.
	crypto: crate::storage::MessageCrypto,
	/// Idle / command read timeout: how long a single read (including the
	/// literal read for APPEND/REPLACE) may stall before the connection is
	/// dropped. Configurable so tests can drive a short deadline.
	read_timeout: Duration,
	/// Days to keep expunged messages in `<account>/.archive/` before the
	/// hourly sweeper removes them. `0` keeps the legacy behaviour:
	/// expunge deletes the on-disk files immediately. The sweep itself runs
	/// in [`crate::cli::serve_tasks::spawn_archive_sweep`].
	retention_days: u64,
	/// The authentication protocol this listener serves (`Imap` or
	/// `Imaps`); tagged on every password attempt through this server so a
	/// per-account `allowed_protocols` set can admit or reject it. Default
	/// `Protocol::Imaps` matches the historical behaviour.
	auth_protocol: crate::config::Protocol,
	/// The bounded queue to the per-account Bayesian trainer, handed to
	/// every session. `None` disables training and STORE answers the same.
	training: Option<crate::antispam::training_queue::TrainingQueue>,
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
			max_connections: MAX_CONNECTIONS,
			crypto: crate::storage::MessageCrypto::disabled(),
			read_timeout: DEFAULT_READ_TIMEOUT,
			retention_days: 0,
			auth_protocol: crate::config::Protocol::Imaps,
			training: None,
		}
	}

	/// Encrypt/decrypt stored message bodies at rest through `crypto`.
	pub fn with_crypto(mut self, crypto: crate::storage::MessageCrypto) -> Self {
		self.crypto = crypto;
		self
	}

	/// Days to keep expunged messages in `<account>/.archive/` before the
	/// hourly sweeper removes them. `0` keeps the legacy behaviour.
	pub fn with_retention_days(mut self, days: u64) -> Self {
		self.retention_days = days;
		self
	}

	/// Cap concurrent connections for this listener (0 keeps the default).
	pub fn with_max_connections(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_connections = max;
		}
		self
	}

	/// Set the per-account storage quota applied to sessions.
	pub fn with_quota(mut self, bytes: u64) -> Self {
		self.quota_bytes = bytes;
		self
	}

	/// Accept OAUTHBEARER/XOAUTH2 bearer tokens, verified by `verifier`.
	pub fn with_oauth(mut self, verifier: Arc<crate::oauth::OauthVerifier>) -> Self {
		self.oauth = Some(verifier);
		self
	}

	/// Cap the idle / literal-read deadline. The default is 30 minutes
	/// (RFC 9051 §5.4); production callers leave it alone, but the test
	/// suite tightens it so a stalled APPEND/REPLACE literal does not stall
	/// a test for half an hour.
	pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
		self.read_timeout = timeout;
		self
	}

	/// Provide the `tls-server-end-point` certificate hash, enabling
	/// AUTH=SCRAM-SHA-256-PLUS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Tag every password authentication attempt through this server with
	/// `protocol` so the directory's per-account `allowed_protocols` set
	/// can admit or reject it. Use the [`Protocol`](crate::config::Protocol) value matching the
	/// listener kind (`Protocol::Imaps` for implicit-TLS port 993,
	/// `Protocol::Imap` for the STARTTLS port 143).
	pub fn with_auth_protocol(mut self, protocol: crate::config::Protocol) -> Self {
		self.auth_protocol = protocol;
		self
	}

	/// Attach the training queue, shared with the JMAP state so both
	/// protocols feed the one worker of the process.
	pub fn with_training(mut self, queue: crate::antispam::training_queue::TrainingQueue) -> Self {
		self.training = Some(queue);
		self
	}

	/// Build a session with this server's quota, OAuth and channel-binding.
	fn new_session(&self) -> Session {
		let mut session = Session::new(
			&self.hostname,
			self.data_dir.clone(),
			self.directory.current(),
		)
		.with_quota_limit(self.quota_bytes)
		.with_crypto(self.crypto.clone())
		.with_oauth(self.oauth.clone())
		.with_retention_days(self.retention_days)
		.with_auth_protocol(self.auth_protocol);
		if let Some(cbind) = &self.cbind_data {
			session = session.with_channel_binding(cbind.clone());
		}
		if let Some(queue) = &self.training {
			session = session.with_training(queue.clone());
		}
		session
	}

	/// Accept connections forever.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(self.max_connections));
		loop {
			let (stream, peer) = listener.accept().await?;
			// A dual-stack `::` listener reports an IPv4 peer as
			// `::ffff:a.b.c.d`; canonicalize so the CIDR allowlist the
			// session consults at authentication sees a plain `IpAddr::V4`.
			let peer = crate::net::canonical_peer(peer);
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "IMAP connection limit reached, dropping");
				continue;
			};
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				let _permit = permit;
				tracing::debug!(%peer, "imap connection accepted");
				if let Err(error) = server.handle(stream, Some(peer.ip())).await {
					tracing::debug!(%peer, %error, "imap connection ended with error");
				}
			});
		}
	}

	/// Drive one connection: TLS handshake (or plaintext with STARTTLS),
	/// then the command loop. `peer` is the client IP, used to enforce
	/// app-password CIDR allowlists; `None` for in-memory tests.
	pub async fn handle<S>(&self, stream: S, peer: Option<std::net::IpAddr>) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let (mut stream, mut session): (Box<dyn Connection>, Session) = match self.tls_mode {
			TlsMode::Implicit => {
				let tls = self.tls.accept(stream).await?;
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
		stream.write_all(&greeting.bytes).await?;
		stream.flush().await?;

		let mut decoder = LineDecoder::new();
		let mut buffer = [0u8; 4096];
		// Consecutive BAD responses; too many means an abusive client.
		let mut error_streak = 0u32;
		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					// With NOTIFY active (RFC 5465), poll the selected mailbox at
					// IDLE_POLL intervals while waiting for the next command and
					// push unsolicited EXISTS/EXPUNGE, bounded by self.read_timeout.
					let wait_start = tokio::time::Instant::now();
					let read = loop {
						let poll = if session.notify_active() {
							IDLE_POLL.min(self.read_timeout)
						} else {
							self.read_timeout
						};
						match tokio::time::timeout(poll, stream.read(&mut buffer)).await {
							Ok(Ok(n)) => break n,
							Ok(Err(e)) => return Err(e),
							Err(_) => {
								if !session.notify_active()
									|| wait_start.elapsed() >= self.read_timeout
								{
									tracing::debug!("IMAP idle timeout, closing connection");
									let _ = stream.write_all(b"* BYE idle timeout\r\n").await;
									return Ok(());
								}
								if let Some(notification) = session.check_notify() {
									if stream.write_all(&notification.bytes).await.is_err() {
										return Ok(());
									}
									let _ = stream.flush().await;
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
					stream.write_all(message).await?;
					stream.flush().await?;
					return Ok(());
				}
			};

			let Ok(line) = String::from_utf8(line) else {
				stream.write_all(b"* BAD non-ASCII command\r\n").await?;
				stream.flush().await?;
				error_streak += 1;
				if error_streak >= MAX_ERROR_STREAK {
					let _ = stream.write_all(b"* BYE too many errors\r\n").await;
					return Ok(());
				}
				continue;
			};

			let announcement = line.split_once(' ').and_then(|(_, command)| {
				let command = match command.split_once(' ') {
					Some((verb, rest)) if verb.eq_ignore_ascii_case("UID") => rest,
					_ => command,
				};
				super::command::literal_announcement_in_line(command)
			});
			if announcement.is_some_and(|literal| literal.size > super::command::MAX_APPEND_SIZE) {
				stream.write_all(b"* BYE literal too large\r\n").await?;
				stream.flush().await?;
				return Ok(());
			}

			let mut output = session.command_line(&line);
			// Abuse guard: drop a client that only produces BAD responses.
			if is_bad_response(&output.bytes) {
				error_streak += 1;
				if error_streak >= MAX_ERROR_STREAK {
					let _ = stream.write_all(b"* BYE too many errors\r\n").await;
					return Ok(());
				}
			} else {
				error_streak = 0;
			}
			loop {
				stream.write_all(&output.bytes).await?;
				stream.flush().await?;
				if output.close {
					return Ok(());
				}
				if let Some(size) = output.discard_literal {
					// RFC 7888 §4: a non-synchronizing literal whose command
					// was rejected still has its payload on the wire. Drain
					// exactly `size` bytes (the trailing CRLF, if any, goes
					// back into the line decoder as an empty line) so the
					// bytes never arrive as the next command. The
					// rejection has already been written; nothing more
					// follows, so return to the command loop instead of
					// rewriting the same response.
					match discard::literal(&mut *stream, &mut decoder, size, self.read_timeout)
						.await
					{
						Ok(drained) if drained.complete => {}
						Ok(_) => return Ok(()),
						Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
							stream.write_all(b"* BYE read timeout\r\n").await?;
							stream.flush().await?;
							return Ok(());
						}
						Err(error) => return Err(error),
					}
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
					let mut literal = decoder.take_buffered(size);
					let mut chunk = [0u8; 4096];
					while literal.len() < size {
						let read =
							match tokio::time::timeout(self.read_timeout, stream.read(&mut chunk))
								.await
							{
								Ok(Ok(n)) => n,
								Ok(Err(e)) => return Err(e),
								Err(_) => {
									tracing::debug!("IMAP literal read timeout, closing");
									let _ = stream.write_all(b"* BYE read timeout\r\n").await;
									return Ok(());
								}
							};
						if read == 0 {
							return Ok(());
						}
						let needed = size - literal.len();
						if read <= needed {
							literal.extend_from_slice(&chunk[..read]);
						} else {
							literal.extend_from_slice(&chunk[..needed]);
							decoder.feed(&chunk[needed..read]);
						}
					}
					// Now consume exactly two bytes for the trailer. The
					// decoder keeps any surplus for the next command line.
					let mut trailer = decoder.take_buffered(2);
					while trailer.len() < 2 {
						let read =
							match tokio::time::timeout(self.read_timeout, stream.read(&mut chunk))
								.await
							{
								Ok(Ok(n)) => n,
								Ok(Err(e)) => return Err(e),
								Err(_) => {
									tracing::debug!("IMAP literal trailer timeout, closing");
									let _ = stream.write_all(b"* BYE read timeout\r\n").await;
									return Ok(());
								}
							};
						if read == 0 {
							return Ok(());
						}
						let needed = 2 - trailer.len();
						if read <= needed {
							trailer.extend_from_slice(&chunk[..read]);
						} else {
							trailer.extend_from_slice(&chunk[..needed]);
							decoder.feed(&chunk[needed..read]);
						}
					}
					if trailer == b"\r\n" {
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
					let response = loop {
						match decoder.next_line() {
							Ok(Some(line)) => break line,
							Ok(None) => {
								let read = match tokio::time::timeout(
									self.read_timeout,
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
					// stream. The line decoder keeps its state: compression
					// is a transport layer, and unlike STARTTLS it discards
					// nothing that was already parsed.
					stream = Box::new(super::compress::Deflate::new(stream));
					// break, not continue: this inner loop re-reads the same
					// `output`, whose `compress` flag is still set, so
					// continuing here would wrap the stream forever.
					break;
				}
				if output.upgrade_tls {
					// Pre-handshake bytes are dropped: nothing buffered in
					// plaintext can leak into the TLS session.
					let tls = self.tls.accept(stream).await?;
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
					decoder = LineDecoder::new();
					break;
				}
				if output.idle {
					// Poll for new messages at IDLE_POLL intervals; close after self.read_timeout.
					let idle_start = tokio::time::Instant::now();
					loop {
						match decoder.next_line() {
							Ok(Some(line)) => {
								if line.eq_ignore_ascii_case(b"DONE") {
									break;
								}
								// Anything else during IDLE is ignored.
							}
							Ok(None) => {
								if idle_start.elapsed() >= self.read_timeout {
									tracing::debug!("IMAP idle timeout during IDLE, closing");
									let _ = stream.write_all(b"* BYE idle timeout\r\n").await;
									return Ok(());
								}
								let read =
									match tokio::time::timeout(IDLE_POLL, stream.read(&mut buffer))
										.await
									{
										Ok(Ok(n)) => n,
										Ok(Err(e)) => return Err(e),
										Err(_) => {
											// Poll interval expired; check for new messages.
											if let Some(notification) = session.check_idle() {
												if stream
													.write_all(&notification.bytes)
													.await
													.is_err()
												{
													return Ok(());
												}
												let _ = stream.flush().await;
											}
											continue;
										}
									};
								if read == 0 {
									return Ok(());
								}
								decoder.feed(&buffer[..read]);
							}
							Err(_) => return Ok(()),
						}
					}
					output = session.idle_done();
					continue;
				}
				break;
			}
		}
	}
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "server_tests_compress.rs"]
mod tests_compress;

#[cfg(test)]
#[path = "server_tests_literals.rs"]
mod tests_literals;

#[path = "server_discard.rs"]
mod discard;

#[cfg(test)]
#[path = "server_tests_discard.rs"]
mod tests_discard;
