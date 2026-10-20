//! Write a message to an async stream and flush it. Used by the
//! server loops of every pre-authentication protocol so that one
//! shared function covers the greeting, every response and every
//! error BYE/NO the session may write.
//!
//! Before sign-in the absolute pre-auth deadline covers both the
//! `write_all` and the `flush`, so a peer that stops reading cannot
//! keep the connection alive past the bound. After sign-in the
//! write_all + flush run without a bound; the post-auth clock is
//! deliberately untouched, matching the pre-change behaviour.

use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::net::deadline::{self, SessionClock};

/// Write `msg` to `stream` and flush the stream. Before authentication
/// the absolute pre-auth deadline of `clock` covers both operations; a
/// peer that stops reading will not hold the connection past it.
/// Once authenticated, `stream.write_all(msg)` and `stream.flush()`
/// run without a bound; the post-auth clock is unchanged.
pub async fn write_response<S>(
	stream: &mut S,
	msg: &[u8],
	clock: &SessionClock,
	authenticated: bool,
) -> io::Result<()>
where
	S: AsyncWrite + Unpin + ?Sized,
{
	if authenticated {
		stream.write_all(msg).await?;
		stream.flush().await
	} else {
		deadline::write_all(stream, msg, clock.preauth_until()).await
	}
}
