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
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::smtp::line::LineDecoder;

use super::backend::MailboxBackend;
use super::command::parse;
use super::session::{Response, Session};

const READ_BUFFER: usize = 4096;
/// Idle timeout per RFC 1939's recommended minimum (10 minutes).
const TIMEOUT: Duration = Duration::from_secs(600);

/// A TLS-only POP3 server bound to one listener.
pub struct Server {
	data_dir: PathBuf,
	directory: DirectoryHandle,
	tls: TlsAcceptor,
}

impl Server {
	/// Create a server. TLS is mandatory: POP3 credentials never cross
	/// plaintext.
	pub fn new(data_dir: PathBuf, directory: DirectoryHandle, tls: TlsAcceptor) -> Self {
		Self {
			data_dir,
			directory,
			tls,
		}
	}

	/// Accept connections forever, one task per connection.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		loop {
			let (stream, _) = listener.accept().await?;
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				if let Err(error) = server.handle(stream).await {
					tracing::debug!(%error, "POP3 connection closed");
				}
			});
		}
	}

	async fn handle(&self, stream: TcpStream) -> std::io::Result<()> {
		let stream = self.tls.accept(stream).await?;
		let backend = MailboxBackend::new(self.directory.clone(), self.data_dir.clone());
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

		let is_final = response.is_final();
		stream.write_all(&response.encode()).await?;
		if is_final {
			return Ok(());
		}
	}
}
