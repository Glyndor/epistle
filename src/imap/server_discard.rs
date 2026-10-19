//! Drain rejected IMAP literals while preserving the following command.

use crate::smtp::line::LineDecoder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

pub(super) struct Drain {
	pub complete: bool,
	#[cfg(test)]
	pub peak_storage: usize,
}

pub(super) async fn literal<S: AsyncRead + Unpin + ?Sized>(
	stream: &mut S,
	decoder: &mut LineDecoder,
	size: usize,
	deadline: Instant,
) -> std::io::Result<Drain> {
	let mut remaining = size - decoder.discard_buffered(size);
	let mut chunk = [0u8; 4096];
	#[cfg(test)]
	let mut peak_storage = decoder.buffer_capacity() + chunk.len();
	while remaining > 0 {
		let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
			.await
			.map_err(|_| {
				std::io::Error::new(std::io::ErrorKind::TimedOut, "literal read timeout")
			})??;
		if read == 0 {
			return Ok(Drain {
				complete: false,
				#[cfg(test)]
				peak_storage,
			});
		}
		let consumed = remaining.min(read);
		remaining -= consumed;
		decoder.feed(&chunk[consumed..read]);
		#[cfg(test)]
		{
			peak_storage = peak_storage.max(decoder.buffer_capacity() + chunk.len());
		}
	}
	Ok(Drain {
		complete: true,
		#[cfg(test)]
		peak_storage,
	})
}

/// Drain a rejected literal and report whether the connection stays open.
/// A timeout answers `* BYE read timeout`; a peer that closes mid-literal
/// ends the connection quietly.
pub(super) async fn literal_or_close<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
	stream: &mut S,
	decoder: &mut LineDecoder,
	size: usize,
	deadline: Instant,
) -> std::io::Result<bool> {
	match literal(stream, decoder, size, deadline).await {
		Ok(drained) => Ok(drained.complete),
		Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
			stream.write_all(b"* BYE read timeout\r\n").await?;
			stream.flush().await?;
			Ok(false)
		}
		Err(error) => Err(error),
	}
}

/// Whether a command line announces a non-synchronizing literal above the
/// APPEND limit, which ends the connection. Its payload is already on the
/// wire and draining an arbitrary announced size is not worth it. A
/// synchronizing one goes on to the session, which answers NO [TOOBIG]
/// (RFC 7889 §3) before the client sends any of it.
pub(super) fn oversized_sent_literal(line: &str) -> bool {
	crate::imap::command::literal_announcement_in_line(line).is_some_and(|literal| {
		literal.size > crate::imap::command::MAX_APPEND_SIZE && !literal.synchronizing
	})
}

/// Drop a line that follows a drained literal of a rejected command: its
/// CRLF, the `)` closing a UTF8 APPEND item, or the next message of a
/// MULTIAPPEND. Answering it as a new command would send `* BAD` for an
/// empty line. A further non-synchronizing literal it announces is drained
/// too. `Some(true)` means the next line is still part of that command,
/// `Some(false)` that the command is over, `None` that the connection ends.
pub(super) async fn rejected_tail<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
	stream: &mut S,
	decoder: &mut LineDecoder,
	line: &[u8],
	deadline: Instant,
) -> std::io::Result<Option<bool>> {
	let tail = String::from_utf8_lossy(line);
	let Some(literal) = crate::imap::command::literal_announcement_in_tail(&tail) else {
		return Ok(Some(false));
	};
	if literal.size > crate::imap::command::MAX_APPEND_SIZE {
		stream.write_all(b"* BYE literal too large\r\n").await?;
		stream.flush().await?;
		return Ok(None);
	}
	if literal.synchronizing {
		return Ok(Some(false));
	}
	if !literal_or_close(stream, decoder, literal.size, deadline).await? {
		return Ok(None);
	}
	Ok(Some(true))
}
