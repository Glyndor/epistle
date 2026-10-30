//! Write a message to an async stream and flush it. Used by the
//! server loops of every pre-authentication protocol so that one
//! shared function covers the greeting, every response and every
//! error BYE/NO the session may write.
//!
//! Before sign-in the absolute pre-auth deadline covers both the
//! `write_all` and the `flush`, so a peer that stops reading cannot
//! keep the connection alive past the bound. After sign-in the write
//! is held to a stall window instead: the peer has to keep accepting
//! bytes, and one that stops accepting for longer than the window
//! loses the connection and its listener slot. The window is not a
//! budget for the whole message, so a peer that reads slowly keeps its
//! session.

use std::io;

use tokio::io::AsyncWrite;

use crate::net::deadline::{self, SessionClock};

/// Write `msg` to `stream` and flush the stream. Before authentication
/// the absolute pre-auth deadline of `clock` covers both operations; a
/// peer that stops reading will not hold the connection past it. Once
/// authenticated, the write is held to the stall window of `clock`: the
/// peer has to keep accepting bytes, and one that stops accepting for
/// longer than the window loses the connection.
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
		deadline::write_all_progressing(stream, msg, clock.write_stall()).await
	} else {
		deadline::write_all(stream, msg, clock.preauth_until()).await
	}
}
