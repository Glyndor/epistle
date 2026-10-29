//! Reading IMAP server responses off the wire with every size and time
//! bounded.
//!
//! The remote server is untrusted. A response is read as a sequence of line
//! fragments, each of which may announce a literal (`{N}` at its end) that
//! follows as exactly `N` raw octets. Every fragment is capped at
//! [`Limits::line`] octets, every literal at [`Limits::literal`], the number
//! of literals in one response at [`MAX_LITERALS`], and every read waits at
//! most [`Limits::idle`] for data. A whole response must also arrive within
//! [`Limits::response`], so a server that drips one octet per idle period
//! cannot hold the migration forever.
//!
//! Nothing here recurses or rescans: each octet is looked at a bounded
//! number of times.

use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::time::Instant;

/// The most literals one response may carry. A FETCH answer for the items
/// the migration asks for carries one (the body); a LIST answer at most one
/// (a mailbox name sent as a literal).
pub(crate) const MAX_LITERALS: usize = 4;

/// The bounds applied to every response.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
	/// Longest line fragment, CRLF included.
	pub(crate) line: usize,
	/// Largest literal, which is the largest message the migration accepts.
	pub(crate) literal: usize,
	/// Longest wait for the next octets of a response.
	pub(crate) idle: Duration,
	/// Longest time one response or complete client command may take.
	pub(crate) response: Duration,
}

/// Why a response could not be read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WireError {
	/// The connection failed or was closed.
	#[error("connection: {0}")]
	Io(#[from] std::io::Error),
	/// The server closed the connection.
	#[error("the server closed the connection")]
	Closed,
	/// A line was longer than the limit.
	#[error("the server sent a line longer than {0} bytes")]
	LineTooLong(usize),
	/// A literal was larger than the limit.
	#[error("the server announced a literal of {size} bytes, over the limit of {limit} bytes")]
	LiteralTooLarge {
		/// The announced size.
		size: u64,
		/// The limit in force.
		limit: usize,
	},
	/// More literals in one response than [`MAX_LITERALS`].
	#[error("the server sent more than {MAX_LITERALS} literals in one response")]
	TooManyLiterals,
	/// No data within the idle limit, or the response took too long.
	#[error("the server stopped answering (timed out)")]
	Timeout,
}

/// One line fragment and the literal it announced, if any. The fragment
/// keeps its `{N}` marker and has its line ending removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment {
	/// The text of the fragment, without CRLF.
	pub(crate) text: Vec<u8>,
	/// The literal that followed it.
	pub(crate) literal: Option<Vec<u8>>,
}

/// A complete server response: one or more segments, the last of which
/// announced no literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
	/// The fragments in order.
	pub(crate) segments: Vec<Segment>,
}

impl Response {
	/// The first fragment's text: the whole response when it carried no
	/// literal, which is the case for every status and continuation line.
	pub(crate) fn head(&self) -> &[u8] {
		self.segments
			.first()
			.map(|segment| segment.text.as_slice())
			.unwrap_or_default()
	}
}

/// Read one complete response from `reader` within `limits`.
pub(crate) async fn read_response<R: AsyncBufRead + Unpin>(
	reader: &mut R,
	limits: &Limits,
) -> Result<Response, WireError> {
	let deadline = Instant::now() + limits.response;
	let mut segments = Vec::new();
	loop {
		let text = read_line(reader, limits, deadline).await?;
		let Some(size) = literal_size(&text) else {
			segments.push(Segment {
				text,
				literal: None,
			});
			return Ok(Response { segments });
		};
		if segments.len() >= MAX_LITERALS {
			return Err(WireError::TooManyLiterals);
		}
		if size > limits.literal as u64 {
			return Err(WireError::LiteralTooLarge {
				size,
				limit: limits.literal,
			});
		}
		let literal = read_exact(reader, size as usize, limits, deadline).await?;
		segments.push(Segment {
			text,
			literal: Some(literal),
		});
	}
}

/// The size a fragment announces with a trailing `{N}`, if it does. A
/// marker without digits is not a literal; a server that sends one gets its
/// line parsed as text and rejected there.
fn literal_size(text: &[u8]) -> Option<u64> {
	let open = text.strip_suffix(b"}")?;
	let start = open.iter().rposition(|&b| b == b'{')?;
	let digits = &open[start + 1..];
	if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
		return None;
	}
	// A size that overflows is reported as `u64::MAX`, which every limit
	// refuses.
	let size = digits.iter().try_fold(0u64, |size, &digit| {
		size.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
	});
	Some(size.unwrap_or(u64::MAX))
}

/// Wait for the next buffered octets, within the idle limit and the
/// response deadline.
async fn fill<'a, R: AsyncBufRead + Unpin>(
	reader: &'a mut R,
	limits: &Limits,
	deadline: Instant,
) -> Result<&'a [u8], WireError> {
	let wait = limits
		.idle
		.min(deadline.saturating_duration_since(Instant::now()));
	match tokio::time::timeout(wait, reader.fill_buf()).await {
		Ok(Ok([])) => Err(WireError::Closed),
		Ok(Ok(buffer)) => Ok(buffer),
		Ok(Err(error)) => Err(WireError::Io(error)),
		Err(_) => Err(WireError::Timeout),
	}
}

/// Read one line, LF-terminated, at most `limits.line` octets long, and
/// return it without its line ending.
async fn read_line<R: AsyncBufRead + Unpin>(
	reader: &mut R,
	limits: &Limits,
	deadline: Instant,
) -> Result<Vec<u8>, WireError> {
	let mut line = Vec::new();
	loop {
		let buffer = fill(reader, limits, deadline).await?;
		let (take, done) = match buffer.iter().position(|&b| b == b'\n') {
			Some(position) => (position + 1, true),
			None => (buffer.len(), false),
		};
		if line.len() + take > limits.line {
			return Err(WireError::LineTooLong(limits.line));
		}
		line.extend_from_slice(&buffer[..take]);
		reader.consume(take);
		if done {
			line.pop();
			if line.last() == Some(&b'\r') {
				line.pop();
			}
			return Ok(line);
		}
	}
}

/// Read exactly `size` octets.
async fn read_exact<R: AsyncBufRead + Unpin>(
	reader: &mut R,
	size: usize,
	limits: &Limits,
	deadline: Instant,
) -> Result<Vec<u8>, WireError> {
	let mut out = Vec::with_capacity(size.min(1 << 20));
	while out.len() < size {
		let buffer = fill(reader, limits, deadline).await?;
		let take = buffer.len().min(size - out.len());
		out.extend_from_slice(&buffer[..take]);
		reader.consume(take);
	}
	Ok(out)
}

#[cfg(test)]
mod tests;
