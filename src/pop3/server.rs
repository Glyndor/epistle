//! POP3 network server: TLS-only (implicit TLS on port 995).
//!
//! POP3 carries the password in USER/PASS, so this server never accepts
//! plaintext connections — there is no cleartext port 110 listener. This file
//! is the socket glue around the unit-tested `session` state machine and is
//! excluded from the no-network coverage gate.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[allow(unused_imports)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::net::conn_limit::{Admission, Refusal, refuse};
use crate::net::deadline::{DEFAULT_PREAUTH_TIMEOUT, SessionClock};
use crate::net::response_writer;
use crate::smtp::line::LineDecoder;

use super::backend::MailboxBackend;
use super::session::{Backend, Response, Session};

const READ_BUFFER: usize = 4096;
/// Idle timeout per RFC 1939's recommended minimum (10 minutes).
pub(crate) const TIMEOUT: Duration = Duration::from_secs(600);
/// Consecutive `-ERR` responses before the connection is dropped (abuse guard).
pub(crate) const MAX_ERROR_STREAK: u32 = 20;
/// Consecutive `[SYS/PERM]` replies (a message that cannot be read) before
/// the connection is dropped. Each may cost a read of a whole message, so
/// the count is separate from the client's own errors and much higher.
pub(crate) const MAX_UNAVAILABLE_STREAK: u32 = 200;
/// Default max concurrent connections for a POP3 listener.
const MAX_CONNECTIONS: usize = 500;

/// What a connection over a cap is told before it is closed.
fn refusal(why: Refusal) -> &'static [u8] {
	match why {
		Refusal::ListenerFull => b"-ERR too many connections, try again later\r\n",
		Refusal::ClientFull => b"-ERR too many connections from your address\r\n",
	}
}

/// A TLS-only POP3 server bound to one listener.
pub struct Server {
	data_dir: PathBuf,
	directory: DirectoryHandle,
	tls: TlsAcceptor,
	max_connections: usize,
	max_per_ip: usize,
	crypto: crate::storage::MessageCrypto,
	preauth_timeout: Duration,
	/// Shared per-account counter applied after authentication. `None`
	/// keeps the historical behaviour (no per-account cap).
	per_account_counter: Option<Arc<crate::net::per_account_conn::PerAccountCounter>>,
}

impl Server {
	/// Create a server. TLS is mandatory: POP3 credentials never cross
	/// plaintext.
	pub fn new(data_dir: PathBuf, directory: DirectoryHandle, tls: TlsAcceptor) -> Self {
		Self {
			data_dir,
			directory,
			tls,
			max_connections: MAX_CONNECTIONS,
			max_per_ip: crate::net::conn_limit::DEFAULT_MAILBOX_CONNECTIONS_PER_IP,
			crypto: crate::storage::MessageCrypto::disabled(),
			preauth_timeout: DEFAULT_PREAUTH_TIMEOUT,
			per_account_counter: None,
		}
	}

	/// Apply the shared per-account counter after authentication.
	/// `None` keeps the listener free of any per-account cap (the
	/// historical behaviour).
	pub fn with_per_account_counter(
		mut self,
		counter: Arc<crate::net::per_account_conn::PerAccountCounter>,
	) -> Self {
		self.per_account_counter = Some(counter);
		self
	}

	/// Decode stored message bodies through `crypto` when serving RETR/TOP.
	pub fn with_crypto(mut self, crypto: crate::storage::MessageCrypto) -> Self {
		self.crypto = crypto;
		self
	}

	/// Cap concurrent connections for this listener (0 keeps the default).
	pub fn with_max_connections(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_connections = max;
		}
		self
	}

	/// Cap the connections one client may hold on this listener (0 keeps the
	/// default). An IPv6 client is counted by its /64.
	pub fn with_max_connections_per_ip(mut self, max: usize) -> Self {
		if max > 0 {
			self.max_per_ip = max;
		}
		self
	}

	/// Set the deadline for the whole phase before sign-in, counted from the
	/// start of the connection.
	pub fn with_preauth_timeout(mut self, timeout: Duration) -> Self {
		self.preauth_timeout = timeout;
		self
	}

	/// Accept connections forever, one bounded task per connection.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		self.serve_on(listener).await
	}

	/// [`Self::serve`] over any source of connections.
	pub(crate) async fn serve_on<A: crate::net::accept::Accept>(
		self: Arc<Self>,
		listener: A,
	) -> std::io::Result<()> {
		let admission = Admission::new(self.max_connections, self.max_per_ip);
		let mut accepting = crate::net::accept::Accepting::new(listener);
		loop {
			let (stream, peer) = accepting.next().await;
			// A dual-stack `::` listener reports an IPv4 peer as
			// `::ffff:a.b.c.d`; canonicalize so the IP survives every
			// downstream consumer (auth, audit) as a plain `IpAddr::V4`.
			let peer = crate::net::canonical_peer(peer);
			let admitted = match admission.admit(peer.ip()) {
				Ok(admitted) => admitted,
				Err(why) => {
					tracing::warn!(%peer, ?why, "POP3 connection limit reached, refusing");
					refuse(stream, refusal(why));
					continue;
				}
			};
			let server = Arc::clone(&self);
			let peer_ip = peer.ip();
			tokio::spawn(async move {
				let _admitted = admitted;
				if let Err(error) = server.handle(stream, peer_ip).await {
					tracing::debug!(%error, "POP3 connection closed");
				}
			});
		}
	}

	async fn handle<S>(&self, stream: S, peer_ip: std::net::IpAddr) -> std::io::Result<()>
	where
		S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
	{
		let clock = SessionClock::start(self.preauth_timeout, TIMEOUT);
		let stream = crate::tls::accept_until(&self.tls, stream, clock.preauth_until()).await?;
		let backend = MailboxBackend::new_with_crypto(
			self.directory.clone(),
			self.data_dir.clone(),
			self.crypto.clone(),
		);
		run(
			stream,
			backend,
			Some(peer_ip),
			clock,
			self.per_account_counter.clone(),
		)
		.await
	}
}

/// The protocol loop: greet, then read command lines and write responses until
/// the session ends or the peer disconnects.
async fn run<S, B: Backend>(
	mut stream: S,
	backend: B,
	peer_ip: Option<std::net::IpAddr>,
	mut clock: SessionClock,
	per_account_counter: Option<Arc<crate::net::per_account_conn::PerAccountCounter>>,
) -> std::io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut session = Session::new(backend);
	session.set_peer_ip(peer_ip);
	if let Some(counter) = per_account_counter {
		session = session.with_per_account_counter(counter);
	}
	response_writer::write_response(&mut stream, &session.greeting().encode(), &clock, false)
		.await?;

	let mut decoder = LineDecoder::new();
	let mut buffer = [0u8; READ_BUFFER];
	// Consecutive error responses; too many means an abusive client.
	let mut error_streak = 0u32;
	let mut unavailable_streak = 0u32;
	loop {
		let line = match decoder.next_line() {
			Ok(Some(line)) => {
				clock.line_done();
				line
			}
			Ok(None) => {
				let deadline = clock.line(session.is_authenticated());
				let read = match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
					Ok(Ok(n)) => n,
					Ok(Err(error)) => return Err(error),
					Err(_) => return Ok(()),
				};
				if read == 0 {
					return Ok(());
				}
				decoder.feed(&buffer[..read]);
				continue;
			}
			Err(_) => {
				let reply = Response::Err("line too long".to_string());
				response_writer::write_response(
					&mut stream,
					&reply.encode(),
					&clock,
					session.is_authenticated(),
				)
				.await?;
				return Ok(());
			}
		};

		let response = match String::from_utf8(line) {
			Ok(text) => session.handle_line(text.trim_end_matches(['\r', '\n'])),
			Err(_) => Response::Err("non-ASCII command".to_string()),
		};

		// Abuse guard: drop a client that only produces errors, and one
		// that keeps asking for messages that cannot be read. A `[SYS/...]`
		// reply that is not about a message neither counts nor resets.
		// The acceptance of a `USER` does not reset the streak either: it
		// is one half of a sign-in the password can still refuse, so a
		// client that alternates a valid `USER` with a failing `PASS`
		// still reaches the cap.
		if response.is_client_error() {
			error_streak += 1;
		} else if response.is_unavailable() {
			unavailable_streak += 1;
		} else if !matches!(response, Response::Err(_)) && !session.sign_in_pending() {
			error_streak = 0;
			unavailable_streak = 0;
		}
		if error_streak >= MAX_ERROR_STREAK || unavailable_streak >= MAX_UNAVAILABLE_STREAK {
			let reply = Response::Err("too many errors".to_string());
			let _ = response_writer::write_response(
				&mut stream,
				&reply.encode(),
				&clock,
				session.is_authenticated(),
			)
			.await;
			return Ok(());
		}

		let is_final = response.is_final();
		for piece in response.wire() {
			response_writer::write_response(
				&mut stream,
				&piece,
				&clock,
				session.is_authenticated(),
			)
			.await?;
		}
		if is_final {
			return Ok(());
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::duplex;

	fn clock() -> SessionClock {
		SessionClock::start(DEFAULT_PREAUTH_TIMEOUT, TIMEOUT)
	}

	fn backend() -> MailboxBackend {
		let dir = tempfile::tempdir().expect("tempdir");
		let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
		MailboxBackend::new(directory, dir.path().to_path_buf())
	}

	#[tokio::test]
	async fn too_many_errors_closes_connection() {
		let (mut client, server) = duplex(64 * 1024);
		let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
		// Drain the greeting, then spam invalid commands.
		let mut chunk = [0u8; 4096];
		let _ = client.read(&mut chunk).await;
		for _ in 0..25 {
			let _ = client.write_all(b"BOGUS\r\n").await;
		}
		// Read until the connection is closed; the last reply is the abuse error.
		let mut seen = String::new();
		loop {
			let read = client.read(&mut chunk).await.expect("read");
			if read == 0 {
				break;
			}
			seen.push_str(&String::from_utf8_lossy(&chunk[..read]));
		}
		assert!(seen.contains("too many errors"), "{seen}");
		let _ = task.await;
	}

	async fn read_chunk(client: &mut tokio::io::DuplexStream) -> String {
		let mut chunk = [0u8; 4096];
		let read = client.read(&mut chunk).await.expect("read");
		String::from_utf8_lossy(&chunk[..read]).to_string()
	}

	#[tokio::test]
	async fn quit_after_greeting_closes_cleanly() {
		let (mut client, server) = duplex(64 * 1024);
		let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
		let greeting = read_chunk(&mut client).await;
		assert!(greeting.starts_with("+OK"), "{greeting}");
		client.write_all(b"QUIT\r\n").await.expect("write");
		let bye = read_chunk(&mut client).await;
		assert!(bye.starts_with("+OK"), "{bye}");
		// The server closed: the next read yields EOF.
		let mut chunk = [0u8; 16];
		assert_eq!(client.read(&mut chunk).await.expect("read"), 0);
		assert!(task.await.expect("join").is_ok());
	}

	#[tokio::test]
	async fn eof_ends_the_session() {
		let (mut client, server) = duplex(64 * 1024);
		let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
		let _ = read_chunk(&mut client).await;
		drop(client); // client hangs up before any command.
		assert!(task.await.expect("join").is_ok());
	}

	#[tokio::test]
	async fn overlong_line_is_rejected() {
		let (mut client, server) = duplex(256 * 1024);
		let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
		let _ = read_chunk(&mut client).await;
		// A line far longer than the protocol allows.
		let huge = vec![b'A'; 100 * 1024];
		client.write_all(&huge).await.expect("write");
		client.write_all(b"\r\n").await.expect("write");
		let reply = read_chunk(&mut client).await;
		assert!(reply.contains("line too long"), "{reply}");
		let _ = task.await;
	}

	#[tokio::test]
	async fn non_ascii_command_is_rejected() {
		let (mut client, server) = duplex(64 * 1024);
		let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
		let _ = read_chunk(&mut client).await;
		client.write_all(&[0xff, 0xfe]).await.expect("write");
		client.write_all(b"\r\n").await.expect("write");
		let reply = read_chunk(&mut client).await;
		assert!(reply.contains("non-ASCII"), "{reply}");
		// The session stays open after a non-final error; hang up to end it.
		drop(client);
		let _ = task.await;
	}

	#[tokio::test(start_paused = true)]
	async fn idle_timeout_closes_connection() {
		let (mut client, server) = duplex(64 * 1024);
		let task = tokio::spawn(async move { run(server, backend(), None, clock(), None).await });
		let _ = read_chunk(&mut client).await; // greeting
		// Send nothing: the read timeout (paused clock) fires and closes.
		let mut chunk = [0u8; 16];
		assert_eq!(client.read(&mut chunk).await.expect("read"), 0);
		assert!(task.await.expect("join").is_ok());
	}
}

#[cfg(test)]
#[path = "server_tests_conn_limit.rs"]
mod conn_limit_tests;

#[cfg(test)]
#[path = "server_tests_deadline.rs"]
mod deadline_tests;

#[cfg(test)]
#[path = "server_tests_guard.rs"]
mod guard_tests;

#[cfg(test)]
#[path = "server_tests_continuation.rs"]
mod continuation_tests;
