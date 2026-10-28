//! Accepting connections on a listener.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// Something connections are accepted from: a TCP listener, or a scripted
/// one in tests.
pub trait Accept: Send + Sync + 'static {
	/// The connection type.
	type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
	/// Wait for the next connection.
	fn accept(&self) -> impl Future<Output = std::io::Result<(Self::Stream, SocketAddr)>> + Send;
}

impl Accept for TcpListener {
	type Stream = TcpStream;

	fn accept(&self) -> impl Future<Output = std::io::Result<(TcpStream, SocketAddr)>> + Send {
		TcpListener::accept(self)
	}
}

/// Shortest pause after a failed accept that signals resource exhaustion.
const MIN_BACKOFF: Duration = Duration::from_millis(10);

/// Longest pause: the backoff doubles up to here while accepts keep failing.
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// At most one log line per this interval; the rest are counted into it.
const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// The accept side of one listener. A failed accept never ends it: out of
/// file descriptors (EMFILE, ENFILE) or buffer space (ENOBUFS, ENOMEM) it
/// backs off, doubling from 10 ms to 1 s, so it neither spins nor gives
/// up; a connection that died before it was taken (ECONNABORTED and the
/// like) is skipped at once. Every failure is counted in
/// `mail_accept_failed_total` and logged at most every ten seconds.
pub struct Accepting<A> {
	listener: A,
	backoff: Duration,
	last_log: Option<Instant>,
	unlogged: u64,
}

impl<A: Accept> Accepting<A> {
	/// Accept from `listener`.
	pub fn new(listener: A) -> Self {
		Accepting {
			listener,
			backoff: MIN_BACKOFF,
			last_log: None,
			unlogged: 0,
		}
	}

	/// The next connection, however many accepts fail first.
	pub async fn next(&mut self) -> (A::Stream, SocketAddr) {
		loop {
			match self.listener.accept().await {
				Ok(connection) => {
					self.backoff = MIN_BACKOFF;
					return connection;
				}
				Err(error) => {
					crate::metrics::accept_failed();
					self.log(&error);
					if exhausts_resources(&error) {
						tokio::time::sleep(self.backoff).await;
						self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
					} else if !per_connection(&error) {
						// Unknown failure: pause for a moment rather than spin.
						tokio::time::sleep(MIN_BACKOFF).await;
					}
				}
			}
		}
	}

	fn log(&mut self, error: &std::io::Error) {
		let now = Instant::now();
		if self
			.last_log
			.is_some_and(|last| now.duration_since(last) < LOG_INTERVAL)
		{
			self.unlogged += 1;
			return;
		}
		tracing::warn!(%error, suppressed = self.unlogged, "accept failed; the listener keeps accepting");
		self.last_log = Some(now);
		self.unlogged = 0;
	}
}

/// The process or the system is out of something a new socket needs.
fn exhausts_resources(error: &std::io::Error) -> bool {
	matches!(
		error.raw_os_error(),
		Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
	)
}

/// One connection failed before it was accepted; the next may be fine.
fn per_connection(error: &std::io::Error) -> bool {
	matches!(
		error.kind(),
		std::io::ErrorKind::ConnectionAborted
			| std::io::ErrorKind::ConnectionReset
			| std::io::ErrorKind::Interrupted
	) || matches!(error.raw_os_error(), Some(libc::EPROTO | libc::EPERM))
}

/// A listener that fails and connects the way a test scripts it.
#[cfg(test)]
pub(crate) mod tests;
