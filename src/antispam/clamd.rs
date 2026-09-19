//! Fail-open clamd scanning over a Unix socket, without local decompression.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::hook::{HookVerdict, MailHook};
use crate::metrics::Metrics;

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub(crate) const DEFAULT_MAX_BYTES: usize = 25 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const MAX_REPLY_BYTES: usize = 8 * 1024;

/// Scan raw messages using clamd's NUL-framed INSTREAM protocol.
pub struct ClamdHook {
	socket: PathBuf,
	on_found: HookVerdict,
	timeout: Duration,
	max_bytes: usize,
	metrics: Option<Arc<Metrics>>,
	started: Instant,
	last_warning: AtomicU64,
}

impl ClamdHook {
	/// Use quarantine on detection, a 30 second deadline, and a 25 MiB limit.
	pub fn new(socket: PathBuf) -> Self {
		Self {
			socket,
			on_found: HookVerdict::Quarantine,
			timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
			max_bytes: DEFAULT_MAX_BYTES,
			metrics: None,
			started: Instant::now(),
			last_warning: AtomicU64::new(u64::MAX),
		}
	}

	/// Set the verdict for a detected signature.
	pub fn with_on_found(mut self, on_found: HookVerdict) -> Self {
		self.on_found = on_found;
		self
	}

	/// Bound the complete socket exchange, including connection and writes.
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Skip messages larger than this many bytes before opening the socket.
	pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
		self.max_bytes = max_bytes;
		self
	}

	/// Attach the server's shared failure and skip counters.
	pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	async fn exchange(
		&self,
		mut stream: impl AsyncRead + AsyncWrite + Unpin,
		raw: &[u8],
	) -> io::Result<HookVerdict> {
		stream.write_all(b"zINSTREAM\0").await?;
		for chunk in raw.chunks(CHUNK_BYTES) {
			stream
				.write_all(&(chunk.len() as u32).to_be_bytes())
				.await?;
			stream.write_all(chunk).await?;
		}
		stream.write_all(&[0; 4]).await?;

		// Bound allocation even if the peer never supplies the terminator.
		let mut reader = BufReader::new(stream.take((MAX_REPLY_BYTES + 1) as u64));
		let mut reply = Vec::new();
		reader.read_until(0, &mut reply).await?;
		if reply.len() > MAX_REPLY_BYTES || reply.last() != Some(&0) {
			return Err(io::Error::other("invalid clamd reply framing"));
		}
		let reply = std::str::from_utf8(&reply[..reply.len() - 1])
			.map_err(|_| io::Error::other("invalid clamd reply encoding"))?;
		if reply == "stream: OK" {
			return Ok(HookVerdict::Accept);
		}
		if let Some(signature) = reply
			.strip_prefix("stream: ")
			.and_then(|value| value.strip_suffix(" FOUND"))
			.filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
		{
			tracing::warn!(
				signature,
				message_bytes = raw.len(),
				"clamd detected a signature"
			);
			return Ok(self.on_found);
		}
		// Never include an unrecognized reply in logs: it may contain message data.
		Err(io::Error::other(if reply.ends_with(" ERROR") {
			"clamd returned an error"
		} else {
			"unrecognized clamd reply"
		}))
	}

	fn failed(&self, error: &dyn std::fmt::Display, now: Duration) -> HookVerdict {
		if let Some(metrics) = &self.metrics {
			metrics.scanner_clamd_failed();
		}
		// Supply monotonic elapsed time so clock jumps cannot bypass the limit.
		let now_nanos = u64::try_from(now.as_nanos()).unwrap_or(u64::MAX - 1);
		if self
			.last_warning
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
				(last == u64::MAX || now_nanos.saturating_sub(last) >= 60_000_000_000)
					.then_some(now_nanos)
			})
			.is_ok()
		{
			tracing::warn!(%error, "clamd scan failed; accepting");
		}
		HookVerdict::Accept
	}

	fn scan_with<'a, S, F>(
		&'a self,
		raw: &[u8],
		connect: F,
	) -> Pin<Box<dyn Future<Output = HookVerdict> + Send + 'a>>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'a,
		F: Future<Output = io::Result<S>> + Send + 'a,
	{
		if raw.len() > self.max_bytes {
			return Box::pin(async move {
				if let Some(metrics) = &self.metrics {
					metrics.scanner_clamd_skipped();
				}
				HookVerdict::Accept
			});
		}
		let body = raw.to_vec();
		Box::pin(async move {
			let exchange = async { self.exchange(connect.await?, &body).await };
			match tokio::time::timeout(self.timeout, exchange).await {
				Ok(Ok(verdict)) => verdict,
				Ok(Err(error)) => self.failed(&error, self.started.elapsed()),
				Err(error) => self.failed(&error, self.started.elapsed()),
			}
		})
	}
}

impl MailHook for ClamdHook {
	fn scan(&self, raw: &[u8]) -> Pin<Box<dyn Future<Output = HookVerdict> + Send + '_>> {
		self.scan_with(raw, UnixStream::connect(&self.socket))
	}
}

#[cfg(test)]
#[path = "clamd_stream_tests.rs"]
mod stream_tests;

#[cfg(test)]
#[path = "clamd_tests.rs"]
mod tests;
