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
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::smtp::line::LineDecoder;

use super::command;
use super::session::{Backend, Response, Session};
use super::store::ScriptStore;

const READ_BUFFER: usize = 4096;
/// Idle timeout before the connection is dropped (30 minutes).
const TIMEOUT: Duration = Duration::from_secs(1800);
/// The largest script literal accepted, guarding against memory exhaustion.
const MAX_LITERAL: usize = 1 << 20;

/// Storage/auth backend backed by the live directory and the accounts tree.
struct DirectoryBackend {
	directory: DirectoryHandle,
	accounts_root: PathBuf,
}

impl Backend for DirectoryBackend {
	fn verify(&self, authcid: &str, password: &str) -> Option<String> {
		self.directory.current().authenticate(authcid, password)
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
}

impl Server {
	/// Create a server rooted at `data_dir`.
	pub fn new(data_dir: PathBuf, directory: DirectoryHandle, tls: TlsAcceptor) -> Self {
		Self {
			directory,
			accounts_root: data_dir.join("accounts"),
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
					tracing::debug!(%error, "ManageSieve connection closed");
				}
			});
		}
	}

	async fn handle(&self, stream: TcpStream) -> std::io::Result<()> {
		let backend = DirectoryBackend {
			directory: self.directory.clone(),
			accounts_root: self.accounts_root.clone(),
		};
		let mut session = Session::new(backend, false);
		let mut stream: Box<dyn Connection> = Box::new(stream);

		stream.write_all(&session.greeting().encode()).await?;
		stream.flush().await?;

		let mut decoder = LineDecoder::new();
		let mut buffer = [0u8; READ_BUFFER];
		loop {
			let Some(line) = read_line(&mut stream, &mut decoder, &mut buffer).await? else {
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
				Some(literal) if literal.len > MAX_LITERAL => {
					write(&mut stream, &Response::No(Some("Script too large.".into()))).await?;
					continue;
				}
				Some(literal) => {
					Some(read_literal(&mut stream, &mut decoder, &mut buffer, literal.len).await?)
				}
				None => None,
			};

			let response = match command::parse(&line, literal) {
				Ok(command) => session.handle(command),
				Err(_) => Response::No(Some("Bad command.".into())),
			};
			let upgrade = response.starts_tls();
			let close = response.is_final();
			write(&mut stream, &response).await?;
			if close {
				return Ok(());
			}
			if upgrade {
				let upgraded = self.tls.accept(stream).await?;
				stream = Box::new(upgraded);
				session.set_tls();
				decoder = LineDecoder::new();
				// RFC 5804 §2.2: re-issue capabilities after the TLS handshake.
				stream.write_all(&session.greeting().encode()).await?;
				stream.flush().await?;
			}
		}
	}
}

/// Read one command line, or `None` on clean EOF/timeout.
async fn read_line(
	stream: &mut Box<dyn Connection>,
	decoder: &mut LineDecoder,
	buffer: &mut [u8],
) -> std::io::Result<Option<Vec<u8>>> {
	loop {
		match decoder.next_line() {
			Ok(Some(line)) => return Ok(Some(line)),
			Ok(None) => {}
			Err(_) => return Ok(None),
		}
		let read = match tokio::time::timeout(TIMEOUT, stream.read(buffer)).await {
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

/// Read exactly `size` literal octets. The trailing CRLF after the literal is
/// left for the next `read_line`, which skips it as a blank line.
async fn read_literal(
	stream: &mut Box<dyn Connection>,
	decoder: &mut LineDecoder,
	buffer: &mut [u8],
	size: usize,
) -> std::io::Result<Vec<u8>> {
	let mut literal = decoder.take_buffered(size);
	while literal.len() < size {
		let read = stream.read(buffer).await?;
		if read == 0 {
			break;
		}
		let needed = size - literal.len();
		if read <= needed {
			literal.extend_from_slice(&buffer[..read]);
		} else {
			literal.extend_from_slice(&buffer[..needed]);
			decoder.feed(&buffer[needed..read]);
		}
	}
	Ok(literal)
}

/// Write a response and flush.
async fn write(stream: &mut Box<dyn Connection>, response: &Response) -> std::io::Result<()> {
	stream.write_all(&response.encode()).await?;
	stream.flush().await
}

/// A boxable bidirectional stream (plain or TLS).
trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}
