//! Drain rejected IMAP literals while preserving the following command.

use crate::smtp::line::LineDecoder;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

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
