//! Drain rejected IMAP literals while preserving the following command.

use crate::smtp::line::LineDecoder;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) struct Drain {
	pub complete: bool,
	#[cfg(test)]
	pub peak_storage: usize,
}

pub(super) async fn literal<S: AsyncRead + Unpin + ?Sized>(
	stream: &mut S,
	decoder: &mut LineDecoder,
	size: usize,
	deadline: Duration,
) -> std::io::Result<Drain> {
	let mut remaining = size - decoder.discard_buffered(size);
	let mut chunk = [0u8; 4096];
	#[cfg(test)]
	let mut peak_storage = decoder.buffer_capacity() + chunk.len();
	while remaining > 0 {
		let read = tokio::time::timeout(deadline, stream.read(&mut chunk))
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
	deadline: Duration,
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
