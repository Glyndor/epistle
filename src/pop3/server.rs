//! POP3 network server: TLS-only (implicit TLS on port 995).
//!
//! POP3 carries the password in USER/PASS, so this server never accepts
//! plaintext connections — there is no cleartext port 110 listener. This file
//! is the socket glue around the unit-tested `session` state machine and is
//! excluded from the no-network coverage gate.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::smtp::line::LineDecoder;

use super::backend::MailboxBackend;
use super::command::parse;
use super::session::{Response, Session};

const READ_BUFFER: usize = 4096;
/// Idle timeout per RFC 1939's recommended minimum (10 minutes).
const TIMEOUT: Duration = Duration::from_secs(600);
/// Consecutive `-ERR` responses before the connection is dropped (abuse guard).
const MAX_ERROR_STREAK: u32 = 20;
/// Default max concurrent connections for a POP3 listener.
const MAX_CONNECTIONS: usize = 500;

/// A TLS-only POP3 server bound to one listener.
pub struct Server {
	data_dir: PathBuf,
	directory: DirectoryHandle,
	tls: TlsAcceptor,
	max_connections: usize,
	crypto: crate::storage::MessageCrypto,
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
			crypto: crate::storage::MessageCrypto::disabled(),
		}
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

	/// Accept connections forever, one bounded task per connection.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(self.max_connections));
		loop {
			let (stream, peer) = listener.accept().await?;
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "POP3 connection limit reached, dropping");
				continue;
			};
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				let _permit = permit;
				if let Err(error) = server.handle(stream).await {
					tracing::debug!(%error, "POP3 connection closed");
				}
			});
		}
	}

	async fn handle(&self, stream: TcpStream) -> std::io::Result<()> {
		let stream = self.tls.accept(stream).await?;
		let backend = MailboxBackend::new_with_crypto(
			self.directory.clone(),
			self.data_dir.clone(),
			self.crypto.clone(),
		);
		run(stream, backend).await
	}
}

/// The protocol loop: greet, then read command lines and write responses until
/// the session ends or the peer disconnects.
async fn run<S>(mut stream: S, backend: MailboxBackend) -> std::io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut session = Session::new(backend);
	stream.write_all(&session.greeting().encode()).await?;

	let mut decoder = LineDecoder::new();
	let mut buffer = [0u8; READ_BUFFER];
	// Consecutive error responses; too many means an abusive client.
	let mut error_streak = 0u32;
	loop {
		let line = match decoder.next_line() {
			Ok(Some(line)) => line,
			Ok(None) => {
				let read = match tokio::time::timeout(TIMEOUT, stream.read(&mut buffer)).await {
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
				stream.write_all(&reply.encode()).await?;
				return Ok(());
			}
		};

		let response = match String::from_utf8(line) {
			Ok(text) => match parse(text.trim_end_matches(['\r', '\n'])) {
				Ok(command) => session.handle(command),
				Err(_) => Response::Err("invalid command".to_string()),
			},
			Err(_) => Response::Err("non-ASCII command".to_string()),
		};

		// Abuse guard: drop a client that only produces errors.
		if matches!(response, Response::Err(_)) {
			error_streak += 1;
			if error_streak >= MAX_ERROR_STREAK {
				let reply = Response::Err("too many errors".to_string());
				let _ = stream.write_all(&reply.encode()).await;
				return Ok(());
			}
		} else {
			error_streak = 0;
		}

		let is_final = response.is_final();
		stream.write_all(&response.encode()).await?;
		if is_final {
			return Ok(());
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::duplex;

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
		let task = tokio::spawn(async move { run(server, backend()).await });
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
		let task = tokio::spawn(async move { run(server, backend()).await });
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
		let task = tokio::spawn(async move { run(server, backend()).await });
		let _ = read_chunk(&mut client).await;
		drop(client); // client hangs up before any command.
		assert!(task.await.expect("join").is_ok());
	}

	#[tokio::test]
	async fn overlong_line_is_rejected() {
		let (mut client, server) = duplex(256 * 1024);
		let task = tokio::spawn(async move { run(server, backend()).await });
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
		let task = tokio::spawn(async move { run(server, backend()).await });
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
		let task = tokio::spawn(async move { run(server, backend()).await });
		let _ = read_chunk(&mut client).await; // greeting
		// Send nothing: the read timeout (paused clock) fires and closes.
		let mut chunk = [0u8; 16];
		assert_eq!(client.read(&mut chunk).await.expect("read"), 0);
		assert!(task.await.expect("join").is_ok());
	}
}
