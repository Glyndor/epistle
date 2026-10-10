//! ManageSieve network server (RFC 5804): plaintext on port 4190 with a
//! mandatory STARTTLS upgrade before authentication.
//!
//! This is the socket glue around the unit-tested `session` state machine and
//! `store`; it is excluded from the no-network coverage gate. Script content is
//! carried in non-synchronizing literals (`{n+}`), which is what real clients
//! (Thunderbird, Roundcube) send.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::smtp::line::LineDecoder;

use super::command;
use super::session::{Backend, Response, Session};
use super::store::ScriptStore;

const READ_BUFFER: usize = 4096;
/// Idle timeout before the connection is dropped (30 minutes).
const TIMEOUT: Duration = Duration::from_secs(1800);
/// Pre-authentication read deadline. An unauthenticated client must
/// not be able to hold a connection slot forever, so the deadline is
/// much shorter than the post-auth one.
const DEFAULT_PREAUTH_TIMEOUT: Duration = Duration::from_secs(60);
/// Default maximum script literal size (1 MiB). Configurable per server
/// so the test suite can drive a small bound.
const DEFAULT_MAX_LITERAL: usize = 1 << 20;
/// Default max concurrent connections for a ManageSieve listener.
const MAX_CONNECTIONS: usize = 100;

/// Storage/auth backend backed by the live directory and the accounts tree.
struct DirectoryBackend {
	directory: DirectoryHandle,
	accounts_root: PathBuf,
}

impl Backend for DirectoryBackend {
	fn verify(
		&self,
		authcid: &str,
		password: &str,
		peer_ip: Option<std::net::IpAddr>,
	) -> Option<String> {
		// Route through the directory's ban-aware path so the ban store
		// sees this attempt. ManageSieve only authenticates one protocol;
		// the per-account `allowed_protocols` set must opt in here for
		// an account to reach its scripts, and the wire response still
		// carries no oracle.
		self.directory.current().authenticate_with_ip(
			authcid,
			password,
			peer_ip,
			crate::config::Protocol::ManageSieve,
		)
	}
	fn store(&self, account: &str) -> ScriptStore {
		ScriptStore::new(&self.accounts_root, account)
	}
}

/// A ManageSieve server bound to one listener.
pub struct Server {
	directory: DirectoryHandle,
	accounts_root: PathBuf,
	tls: TlsAcceptor,
	max_connections: usize,
	max_literal: usize,
	preauth_timeout: Duration,
}

impl Server {
	/// Create a server rooted at `data_dir`.
	pub fn new(data_dir: PathBuf, directory: DirectoryHandle, tls: TlsAcceptor) -> Self {
		Self {
			directory,
			accounts_root: data_dir.join("accounts"),
			tls,
			max_connections: MAX_CONNECTIONS,
			max_literal: DEFAULT_MAX_LITERAL,
			preauth_timeout: DEFAULT_PREAUTH_TIMEOUT,
		}
	}

	/// Cap concurrent connections for this listener (0 keeps the default).
	pub fn with_max_connections(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_connections = max;
		}
		self
	}

	/// Set the maximum script literal size accepted by this server.
	/// `0` keeps the default of 1 MiB; tests use a small bound so they
	/// can drive a "too large" rejection without sending megabytes.
	pub fn with_max_literal(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_literal = max;
		}
		self
	}

	/// Set the pre-authentication read deadline. The default is 60
	/// seconds, short enough that an idle attacker cannot exhaust the
	/// listener's connection slots. Tests use a 2-second bound so a
	/// regression is caught in seconds, not minutes.
	pub fn with_preauth_timeout(mut self, timeout: Duration) -> Self {
		self.preauth_timeout = timeout;
		self
	}

	/// Accept connections forever, one bounded task per connection.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(self.max_connections));
		loop {
			let (stream, peer) = listener.accept().await?;
			// A dual-stack `::` listener reports an IPv4 peer as
			// `::ffff:a.b.c.d`; canonicalize so the audit channel and the
			// ban-aware authentication path see a plain `IpAddr::V4`.
			let peer = crate::net::canonical_peer(peer);
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "ManageSieve connection limit reached, dropping");
				continue;
			};
			let server = Arc::clone(&self);
			let peer_ip = peer.ip();
			tokio::spawn(async move {
				let _permit = permit;
				if let Err(error) = server.handle(stream, peer_ip).await {
					tracing::debug!(%error, "ManageSieve connection closed");
				}
			});
		}
	}

	async fn handle(
		&self,
		stream: tokio::net::TcpStream,
		peer_ip: std::net::IpAddr,
	) -> std::io::Result<()> {
		self.handle_inner(stream, peer_ip).await
	}

	/// Drive one connection from the command loop, given any bidirectional
	/// stream. Public so the test suite can drive it with an in-memory
	/// `tokio::io::duplex` pair without going through a real listener.
	pub async fn handle_stream<S>(&self, stream: S) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		self.handle_inner(
			stream,
			std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
		)
		.await
	}

	/// Test-only: drive the command loop with a pre-authenticated
	/// session for `account`. Avoids a STARTTLS handshake so the test
	/// can use an in-memory `tokio::io::duplex` pair directly.
	#[cfg(test)]
	pub async fn handle_preauth_for_test<S>(&self, stream: S, account: &str) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let backend = DirectoryBackend {
			directory: self.directory.clone(),
			accounts_root: self.accounts_root.clone(),
		};
		let mut session = Session::new(backend, true);
		session.adopt_account_for_test(account);
		run_command_loop(
			stream,
			session,
			self.max_literal,
			self.preauth_timeout,
			None,
		)
		.await
	}

	async fn handle_inner<S>(&self, stream: S, peer_ip: std::net::IpAddr) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let backend = DirectoryBackend {
			directory: self.directory.clone(),
			accounts_root: self.accounts_root.clone(),
		};
		let mut session = Session::new(backend, false);
		session.set_peer_ip(Some(peer_ip));
		run_command_loop(
			stream,
			session,
			self.max_literal,
			self.preauth_timeout,
			Some(&self.tls),
		)
		.await
	}
}

/// Drive the command loop with the given pre-built session. Both the
/// real connection path and the test-only pre-authenticated path share
/// this body so the literal-framing rules cannot diverge.
async fn run_command_loop<S, B>(
	stream: S,
	mut session: Session<B>,
	max_literal: usize,
	preauth_timeout: Duration,
	tls_acceptor: Option<&tokio_rustls::TlsAcceptor>,
) -> std::io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	B: Backend,
{
	let mut stream: Box<dyn Connection> = Box::new(stream);
	stream.write_all(&session.greeting().encode()).await?;
	stream.flush().await?;

	let mut decoder = LineDecoder::new();
	let mut buffer = [0u8; READ_BUFFER];
	loop {
		let read_deadline = if session.account_is_some() {
			TIMEOUT
		} else {
			preauth_timeout
		};
		let Some(line) = read_line(&mut stream, &mut decoder, &mut buffer, read_deadline).await?
		else {
			write(
				&mut stream,
				&Response::Bye("Pre-authentication timeout.".into()),
			)
			.await?;
			return Ok(());
		};
		let Ok(line) = String::from_utf8(line) else {
			write(
				&mut stream,
				&Response::No(Some("Non-UTF-8 command.".into())),
			)
			.await?;
			continue;
		};
		if line.trim().is_empty() {
			continue;
		}

		// PUTSCRIPT/CHECKSCRIPT carry a trailing literal with the script.
		let literal = match command::trailing_literal(&line) {
			Some(literal) if literal.len > max_literal => {
				write(&mut stream, &Response::Bye("literal too large".into())).await?;
				return Ok(());
			}
			Some(literal) => {
				// Reject commands whose failure is known before the script arrives.
				// Only a non-synchronizing literal has bytes to discard on rejection.
				let rejection = match command::parse(&line, None) {
					Err(command::ParseError::MissingLiteral) if !session.account_is_some() => {
						Some("Authenticate first.")
					}
					Err(command::ParseError::MissingLiteral) => None,
					Err(_) => Some("Bad command."),
					Ok(_) => None,
				};
				if let Some(message) = rejection {
					write(&mut stream, &Response::No(Some(message.into()))).await?;
					if !literal.synchronizing {
						match discard::literal(
							&mut *stream,
							&mut decoder,
							literal.len,
							read_deadline,
						)
						.await
						{
							Ok(drained) if drained.complete => {}
							Ok(_) => return Ok(()),
							Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
								write(&mut stream, &Response::Bye("read timeout".into())).await?;
								return Ok(());
							}
							Err(error) => return Err(error),
						}
					}
					continue;
				}
				match read_literal(&mut stream, &mut decoder, &mut buffer, literal.len).await? {
					Some(bytes) => Some(bytes),
					None => {
						// The connection closed before the announced
						// literal size arrived: drop the partial payload
						// instead of parsing it as a complete script.
						write(
							&mut stream,
							&Response::No(Some("Literal truncated by connection close.".into())),
						)
						.await?;
						continue;
					}
				}
			}
			None => None,
		};

		let response = session.handle_line(&line, literal);
		let upgrade = response.starts_tls();
		let close = response.is_final();
		write(&mut stream, &response).await?;
		if close {
			return Ok(());
		}
		if upgrade {
			let Some(tls) = tls_acceptor else {
				return Ok(());
			};
			let upgraded = tls.accept(stream).await?;
			stream = Box::new(upgraded);
			session.set_tls();
			decoder = LineDecoder::new();
			stream.write_all(&session.greeting().encode()).await?;
			stream.flush().await?;
		}
	}
}

/// Read one command line, or `None` on clean EOF/timeout. `deadline`
/// is the per-read timeout the caller wants to enforce; the post-auth
/// deadline is generous (30 minutes), the pre-auth deadline is tight
/// so an idle attacker cannot exhaust the listener's connection slots.
async fn read_line(
	stream: &mut Box<dyn Connection>,
	decoder: &mut LineDecoder,
	buffer: &mut [u8],
	deadline: Duration,
) -> std::io::Result<Option<Vec<u8>>> {
	loop {
		match decoder.next_line() {
			Ok(Some(line)) => return Ok(Some(line)),
			Ok(None) => {}
			Err(_) => return Ok(None),
		}
		let read = match tokio::time::timeout(deadline, stream.read(buffer)).await {
			Ok(Ok(n)) => n,
			Ok(Err(error)) => return Err(error),
			Err(_) => return Ok(None),
		};
		if read == 0 {
			return Ok(None);
		}
		decoder.feed(&buffer[..read]);
	}
}

/// Read exactly `size` literal octets, or detect a truncated connection
/// and return `None` so the caller can reject the command. The trailing
/// CRLF after the literal is left for the next `read_line`, which skips
/// it as a blank line.
async fn read_literal(
	stream: &mut Box<dyn Connection>,
	decoder: &mut LineDecoder,
	buffer: &mut [u8],
	size: usize,
) -> std::io::Result<Option<Vec<u8>>> {
	let mut literal = decoder.take_buffered(size);
	while literal.len() < size {
		let read = stream.read(buffer).await?;
		if read == 0 {
			return Ok(None);
		}
		let needed = size - literal.len();
		if read <= needed {
			literal.extend_from_slice(&buffer[..read]);
		} else {
			literal.extend_from_slice(&buffer[..needed]);
			decoder.feed(&buffer[needed..read]);
		}
	}
	Ok(Some(literal))
}

/// Write a response and flush.
async fn write(stream: &mut Box<dyn Connection>, response: &Response) -> std::io::Result<()> {
	stream.write_all(&response.encode()).await?;
	stream.flush().await
}

/// A boxable bidirectional stream (plain or TLS).
trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

#[cfg(test)]
#[path = "server_tests_literals.rs"]
mod tests_literals;

#[path = "server_discard.rs"]
mod discard;

#[cfg(test)]
#[path = "server_tests_discard.rs"]
mod tests_discard;
