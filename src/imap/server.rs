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
const READ_TIMEOUT: Duration = Duration::from_secs(1800);

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
		}
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

	/// Provide the `tls-server-end-point` certificate hash, enabling
	/// AUTH=SCRAM-SHA-256-PLUS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
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
		.with_oauth(self.oauth.clone());
		if let Some(cbind) = &self.cbind_data {
			session = session.with_channel_binding(cbind.clone());
		}
		session
	}

	/// Accept connections forever.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(self.max_connections));
		loop {
			let (stream, peer) = listener.accept().await?;
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "IMAP connection limit reached, dropping");
				continue;
			};
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				let _permit = permit;
				tracing::debug!(%peer, "imap connection accepted");
				if let Err(error) = server.handle(stream).await {
					tracing::debug!(%peer, %error, "imap connection ended with error");
				}
			});
		}
	}

	/// Drive one connection: TLS handshake (or plaintext with STARTTLS),
	/// then the command loop.
	pub async fn handle<S>(&self, stream: S) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let (mut stream, mut session): (Box<dyn Connection>, Session) = match self.tls_mode {
			TlsMode::Implicit => {
				let tls = self.tls.accept(stream).await?;
				(Box::new(tls), self.new_session())
			}
			TlsMode::StartTls => (Box::new(stream), self.new_session().with_starttls()),
		};

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
					let read =
						match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buffer)).await {
							Ok(Ok(n)) => n,
							Ok(Err(e)) => return Err(e),
							Err(_) => {
								tracing::debug!("IMAP idle timeout, closing connection");
								let _ = stream.write_all(b"* BYE idle timeout\r\n").await;
								return Ok(());
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
				if let Some(size) = output.collect_literal {
					// Read exactly `size` literal bytes (plus trailing CRLF
					// which the line decoder will consume as an empty line).
					let mut literal = decoder.take_buffered(size);
					let mut chunk = [0u8; 4096];
					while literal.len() < size {
						let read = stream.read(&mut chunk).await?;
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
					output = session.literal_done(&literal);
					continue;
				}
				if output.collect_auth {
					// Read one SASL continuation line and feed it back.
					let response = loop {
						match decoder.next_line() {
							Ok(Some(line)) => break line,
							Ok(None) => {
								let read = match tokio::time::timeout(
									READ_TIMEOUT,
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
				if output.upgrade_tls {
					// Pre-handshake bytes are dropped: nothing buffered in
					// plaintext can leak into the TLS session.
					let tls = self.tls.accept(stream).await?;
					stream = Box::new(tls);
					session.tls_started();
					decoder = LineDecoder::new();
					break;
				}
				if output.idle {
					// Poll for new messages at IDLE_POLL intervals; close after READ_TIMEOUT.
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
								if idle_start.elapsed() >= READ_TIMEOUT {
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
