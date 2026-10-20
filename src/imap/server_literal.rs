//! Read the octets of an IMAP literal, or the bytes that must follow it.

use crate::smtp::line::LineDecoder;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

/// How reading `size` octets ended.
pub(super) enum Taken {
	/// Exactly `size` octets; anything further stays in the decoder.
	Done(Vec<u8>),
	/// The peer closed the connection first.
	Closed,
	/// `deadline` passed first.
	TimedOut,
}

/// Take exactly `size` octets, from what the decoder already holds and then
/// from `stream`. No read goes past `deadline`, however slowly bytes arrive.
pub(super) async fn take_exact<S: AsyncRead + Unpin + ?Sized>(
	stream: &mut S,
	decoder: &mut LineDecoder,
	size: usize,
	deadline: Instant,
) -> std::io::Result<Taken> {
	let mut taken = decoder.take_buffered(size);
	let mut chunk = [0u8; 4096];
	while taken.len() < size {
		let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
			Ok(result) => result?,
			Err(_) => return Ok(Taken::TimedOut),
		};
		if read == 0 {
			return Ok(Taken::Closed);
		}
		let needed = size - taken.len();
		if read <= needed {
			taken.extend_from_slice(&chunk[..read]);
		} else {
			taken.extend_from_slice(&chunk[..needed]);
			decoder.feed(&chunk[needed..read]);
		}
	}
	Ok(Taken::Done(taken))
}
