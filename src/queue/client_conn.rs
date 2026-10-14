//! The buffered SMTP connection the client drives: one command line out,
//! one (possibly multiline) reply in, each bounded by the wait of its step
//! (see [`crate::queue::timeouts`]).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::DeliveryError;
use tokio::time::timeout;

use crate::queue::timeouts::{DATA_BLOCK_BYTES, Phase};

/// Object-safe stream the connection reads and writes.
pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Buffered SMTP conversation state.
pub(super) struct Conn {
	stream: Box<dyn Stream>,
	buffer: Vec<u8>,
	last_reply: String,
	/// A step timed out or the stream failed: nothing more can be said on it.
	broken: bool,
}

impl Conn {
	pub(super) fn new(stream: Box<dyn Stream>) -> Self {
		Conn {
			stream,
			buffer: Vec::new(),
			last_reply: String::new(),
			broken: false,
		}
	}

	pub(super) fn into_inner(self) -> Box<dyn Stream> {
		self.stream
	}

	pub(super) fn last_reply_contains(&self, needle: &str) -> bool {
		self.last_reply.contains(needle)
	}

	/// Whether a step timed out or the stream failed, so the conversation
	/// cannot go on (not even to say QUIT).
	pub(super) fn is_broken(&self) -> bool {
		self.broken
	}

	/// The outcome of a step bounded by `phase`; running out of time breaks
	/// the connection.
	fn bounded<T>(
		&mut self,
		phase: Phase,
		outcome: Result<Result<T, DeliveryError>, tokio::time::error::Elapsed>,
	) -> Result<T, DeliveryError> {
		outcome.unwrap_or_else(|_| {
			self.broken = true;
			Err(phase.timed_out())
		})
	}

	/// A failed read or write breaks the connection.
	fn failed(&mut self, error: std::io::Error) -> DeliveryError {
		self.broken = true;
		DeliveryError::Transient(error.to_string())
	}

	/// Send `line` and require the `expected` reply, all within `phase`.
	pub(super) async fn command(
		&mut self,
		line: &str,
		expected: u16,
		phase: Phase,
	) -> Result<(), DeliveryError> {
		let outcome = timeout(phase.limit(), async {
			self.write_line(line).await?;
			self.expect_now(expected).await
		})
		.await;
		self.bounded(phase, outcome)
	}

	/// Write one command line within `phase`.
	pub(super) async fn send(&mut self, line: &str, phase: Phase) -> Result<(), DeliveryError> {
		let outcome = timeout(phase.limit(), self.write_line(line)).await;
		self.bounded(phase, outcome)
	}

	async fn write_line(&mut self, line: &str) -> Result<(), DeliveryError> {
		let written = async {
			self.stream
				.write_all(format!("{line}\r\n").as_bytes())
				.await?;
			self.stream.flush().await
		}
		.await;
		written.map_err(|error| self.failed(error))
	}

	/// Send message data with dot-stuffing and the final terminator, one
	/// block at a time, each within [`Phase::DataBlock`].
	pub(super) async fn send_data(&mut self, data: &[u8]) -> Result<(), DeliveryError> {
		let mut wire = Vec::with_capacity(data.len() + 16);
		for line in data.split_inclusive(|&b| b == b'\n') {
			if line.first() == Some(&b'.') {
				wire.push(b'.');
			}
			wire.extend_from_slice(line);
		}
		if !wire.ends_with(b"\r\n") {
			wire.extend_from_slice(b"\r\n");
		}
		wire.extend_from_slice(b".\r\n");
		for block in wire.chunks(DATA_BLOCK_BYTES) {
			let outcome = timeout(Phase::DataBlock.limit(), async {
				let written = async {
					self.stream.write_all(block).await?;
					self.stream.flush().await
				}
				.await;
				written.map_err(|error| self.failed(error))
			})
			.await;
			self.bounded(Phase::DataBlock, outcome)?;
		}
		Ok(())
	}

	/// Read one (possibly multiline) reply within `phase` and require
	/// `expected`.
	pub(super) async fn expect(
		&mut self,
		expected: u16,
		phase: Phase,
	) -> Result<(), DeliveryError> {
		let outcome = timeout(phase.limit(), self.expect_now(expected)).await;
		self.bounded(phase, outcome)
	}

	async fn expect_now(&mut self, expected: u16) -> Result<(), DeliveryError> {
		let (code, text) = self.read_parsed().await?;
		if code != expected {
			return Err(DeliveryError::from_reply(code, &text));
		}
		Ok(())
	}

	/// Read one (possibly multiline) reply within `phase`: its code and its
	/// full text. `Err` only when no well-formed reply arrived in time.
	pub(super) async fn reply(&mut self, phase: Phase) -> Result<(u16, String), DeliveryError> {
		let outcome = timeout(phase.limit(), self.read_parsed()).await;
		self.bounded(phase, outcome)
	}

	async fn read_parsed(&mut self) -> Result<(u16, String), DeliveryError> {
		let reply = self.read_reply().await?;
		let code: u16 = reply
			.get(..3)
			.and_then(|head| head.parse().ok())
			.ok_or_else(|| DeliveryError::Transient(format!("malformed reply: {reply}")))?;
		self.last_reply = reply.clone();
		Ok((code, reply))
	}

	async fn read_reply(&mut self) -> Result<String, DeliveryError> {
		loop {
			if let Some(reply) = complete_reply(&self.buffer) {
				let text = String::from_utf8_lossy(&self.buffer[..reply]).to_string();
				self.buffer.drain(..reply);
				return Ok(text);
			}
			if self.buffer.len() > 64 * 1024 {
				return Err(DeliveryError::Transient("oversized reply".into()));
			}
			let mut chunk = [0u8; 4096];
			let read = match self.stream.read(&mut chunk).await {
				Ok(read) => read,
				Err(error) => return Err(self.failed(error)),
			};
			if read == 0 {
				self.broken = true;
				return Err(DeliveryError::Transient(
					"connection closed mid-reply".into(),
				));
			}
			self.buffer.extend_from_slice(&chunk[..read]);
		}
	}
}

/// Length of a complete reply in `buffer` (through the final CRLF of its
/// last line), or `None` if more bytes are needed.
pub(super) fn complete_reply(buffer: &[u8]) -> Option<usize> {
	let mut offset = 0;
	loop {
		let rest = &buffer[offset..];
		let line_end = rest.windows(2).position(|w| w == b"\r\n")? + 2;
		let line = &rest[..line_end];
		// A line like `250-...` continues; `250 ...` (or bare code) ends.
		let continues = line.len() >= 4 && line[3] == b'-';
		offset += line_end;
		if !continues {
			return Some(offset);
		}
	}
}
