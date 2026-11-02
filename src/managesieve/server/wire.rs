//! The reads and writes of the ManageSieve command loop: one command line,
//! one literal, one response. Split from `mod.rs`.

use super::*;

/// Read one command line, or `None` on clean EOF/timeout. `deadline` is an
/// absolute instant that incoming bytes do not move; the post-auth one is
/// generous (30 minutes), the pre-auth one is tight so an idle or dripping
/// attacker cannot exhaust the listener's connection slots.
pub(super) async fn read_line(
	stream: &mut Box<dyn Connection>,
	decoder: &mut LineDecoder,
	buffer: &mut [u8],
	deadline: Instant,
) -> std::io::Result<Option<Vec<u8>>> {
	loop {
		match decoder.next_line() {
			Ok(Some(line)) => return Ok(Some(line)),
			Ok(None) => {}
			Err(_) => return Ok(None),
		}
		let read = match tokio::time::timeout_at(deadline, stream.read(buffer)).await {
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

/// Read exactly `size` literal octets, or detect a truncated connection
/// and return `None` so the caller can reject the command. The trailing
/// CRLF after the literal is left for the next `read_line`, which skips
/// it as a blank line. Running past `deadline` is a `TimedOut` error.
pub(super) async fn read_literal(
	stream: &mut Box<dyn Connection>,
	decoder: &mut LineDecoder,
	buffer: &mut [u8],
	size: usize,
	deadline: Instant,
) -> std::io::Result<Option<Vec<u8>>> {
	let mut literal = decoder.take_buffered(size);
	while literal.len() < size {
		let read = tokio::time::timeout_at(deadline, stream.read(buffer))
			.await
			.map_err(|_| {
				std::io::Error::new(std::io::ErrorKind::TimedOut, "literal read timeout")
			})??;
		if read == 0 {
			return Ok(None);
		}
		let needed = size - literal.len();
		if read <= needed {
			literal.extend_from_slice(&buffer[..read]);
		} else {
			literal.extend_from_slice(&buffer[..needed]);
			decoder.feed(&buffer[needed..read]);
		}
	}
	Ok(Some(literal))
}

/// Write a response and flush. Before sign-in the absolute pre-auth
/// deadline covers both operations so a peer that stops reading cannot
/// keep the connection alive past it; after sign-in the write is held
/// to the stall window, so a peer that stops accepting the bytes loses
/// the connection and the listener slot it holds. Wrapper around
/// [`response_writer::write_response`] that takes a [`Response`] and
/// threads it through the shared writer.
pub(super) async fn write_response(
	stream: &mut Box<dyn Connection>,
	response: &Response,
	clock: &SessionClock,
	authenticated: bool,
) -> std::io::Result<()> {
	response_writer::write_response(stream, &response.encode(), clock, authenticated).await
}
