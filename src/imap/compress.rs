//! COMPRESS=DEFLATE (RFC 4978): a persistent deflate stream over the
//! connection, in both directions.
//!
//! The compression context lives for the rest of the connection rather than
//! per message. That is where the ratio comes from: IMAP repeats the same
//! command names, flag names and header keys endlessly. Both directions use
//! **raw** deflate (no zlib header), which is what RFC 4978 §2 specifies, and
//! every write ends in a sync flush so the peer can decode a complete response
//! without waiting for the next one.
//!
//! Wrapping the stream, rather than compressing at each call site, is
//! deliberate: the connection loop reads and writes in about fifteen places,
//! and one left uncompressed desynchronises the deflate context for the rest
//! of the session. That surfaces as a client that hangs, not as an error
//! anyone can read.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Working buffer size for one inflate or deflate pass.
const CHUNK: usize = 8 * 1024;

/// A connection with RFC 4978 deflate applied in both directions.
pub(super) struct Deflate<S> {
	inner: S,
	compress: Compress,
	decompress: Decompress,
	/// Compressed bytes read from `inner` and not yet inflated.
	raw_in: Vec<u8>,
	/// How much of `raw_in` the inflater has consumed.
	raw_in_pos: usize,
	/// Inflated bytes not yet handed to the caller.
	plain_in: VecDeque<u8>,
	/// Compressed bytes the inner stream has not accepted yet.
	raw_out: VecDeque<u8>,
	/// Set once the inner stream reports end of file.
	eof: bool,
}

impl<S> Deflate<S> {
	/// Wrap `inner`. Called only after the `COMPRESS DEFLATE` OK has been
	/// written and flushed in the clear, which RFC 4978 §3 requires: the
	/// tagged response to the command itself is not compressed.
	pub(super) fn new(inner: S) -> Self {
		Deflate {
			inner,
			// `zlib_header = false` is raw deflate at the default 15-bit window,
			// which is what RFC 4978 §2 asks for. The explicit window-bits
			// constructors are behind flate2's `any_zlib` feature and would pull
			// in a C zlib for a parameter we would set to the default anyway.
			compress: Compress::new(Compression::default(), false),
			decompress: Decompress::new(false),
			raw_in: Vec::new(),
			raw_in_pos: 0,
			plain_in: VecDeque::new(),
			raw_out: VecDeque::new(),
			eof: false,
		}
	}
}

impl<S: AsyncWrite + Unpin> Deflate<S> {
	/// Push `raw_out` into the inner stream until it is empty or the stream
	/// blocks.
	fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		while !self.raw_out.is_empty() {
			let this = &mut *self;
			let bytes = this.raw_out.make_contiguous();
			match Pin::new(&mut this.inner).poll_write(cx, bytes) {
				Poll::Ready(Ok(0)) => {
					return Poll::Ready(Err(io::Error::new(
						io::ErrorKind::WriteZero,
						"the peer stopped accepting the compressed stream",
					)));
				}
				Poll::Ready(Ok(written)) => {
					self.raw_out.drain(..written);
				}
				Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
				Poll::Pending => return Poll::Pending,
			}
		}
		Poll::Ready(Ok(()))
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for Deflate<S> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		loop {
			if !self.plain_in.is_empty() {
				let take = self.plain_in.len().min(buf.remaining());
				let bytes: Vec<u8> = self.plain_in.drain(..take).collect();
				buf.put_slice(&bytes);
				return Poll::Ready(Ok(()));
			}
			if self.eof {
				// Zero filled bytes is how tokio spells EOF.
				return Poll::Ready(Ok(()));
			}

			if self.raw_in_pos < self.raw_in.len() {
				let before_in = self.decompress.total_in();
				let before_out = self.decompress.total_out();
				let mut out = vec![0u8; CHUNK];
				let this = &mut *self;
				let start = this.raw_in_pos;
				let status = this
					.decompress
					.decompress(&this.raw_in[start..], &mut out, FlushDecompress::None)
					.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
				let consumed = usize::try_from(self.decompress.total_in() - before_in).unwrap_or(0);
				let produced =
					usize::try_from(self.decompress.total_out() - before_out).unwrap_or(0);
				self.raw_in_pos += consumed;
				self.plain_in.extend(&out[..produced]);
				if status == Status::StreamEnd {
					self.eof = true;
				}
				if produced > 0 || self.eof {
					continue;
				}
				if consumed > 0 {
					continue;
				}
				// It needs more compressed input before it can produce
				// anything. Fall through to the refill, which keeps what is
				// left: a deflate block split across two reads must be
				// rejoined, not decoded as two truncated ones.
			}

			let mut chunk = vec![0u8; CHUNK];
			let mut read_buf = ReadBuf::new(&mut chunk);
			match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
				Poll::Ready(Ok(())) => {
					let filled = read_buf.filled().len();
					if filled == 0 {
						self.eof = true;
						return Poll::Ready(Ok(()));
					}
					// Drop only what the inflater has already consumed and
					// append the new bytes to the remainder.
					let consumed_so_far = self.raw_in_pos;
					self.raw_in.drain(..consumed_so_far);
					self.raw_in_pos = 0;
					self.raw_in.extend_from_slice(&chunk[..filled]);
				}
				Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
				Poll::Pending => return Poll::Pending,
			}
		}
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Deflate<S> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		// Whatever is already deflated goes out before `buf` is touched, so a
		// `Pending` here can never deflate the same bytes twice.
		if !self.raw_out.is_empty() {
			match self.drain(cx) {
				Poll::Ready(Ok(())) => {}
				Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
				Poll::Pending => return Poll::Pending,
			}
		}
		if buf.is_empty() {
			return Poll::Ready(Ok(0));
		}

		let before_in = self.compress.total_in();
		let before_out = self.compress.total_out();
		let mut out = vec![0u8; buf.len() + CHUNK];
		let this = &mut *self;
		this.compress
			.compress(buf, &mut out, FlushCompress::Sync)
			.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
		let consumed = usize::try_from(self.compress.total_in() - before_in).unwrap_or(0);
		let produced = usize::try_from(self.compress.total_out() - before_out).unwrap_or(0);
		self.raw_out.extend(&out[..produced]);

		// Opportunistic: whatever the inner stream will not take now is left
		// for the next write or the flush that follows it.
		let _ = self.drain(cx);
		if consumed == 0 {
			// Nothing consumed and nothing produced would spin `write_all`.
			return Poll::Pending;
		}
		Poll::Ready(Ok(consumed))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		match self.drain(cx) {
			Poll::Ready(Ok(())) => {}
			other => return other,
		}
		Pin::new(&mut self.inner).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		match self.drain(cx) {
			Poll::Ready(Ok(())) => {}
			other => return other,
		}
		Pin::new(&mut self.inner).poll_shutdown(cx)
	}
}

#[cfg(test)]
#[path = "compress_tests.rs"]
mod tests;
