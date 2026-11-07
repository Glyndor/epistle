//! Reading an mbox stream one entry at a time, with every entry bounded by
//! the message size limit.
//!
//! The stream is read in chunks and one line at a time. An entry that goes
//! past the limit is refused, and the rest of it is read and dropped up to
//! the next `From ` line, so the memory an import takes does not grow with
//! the size of the entry it refused.

use std::io::Read;

/// The bytes read from the stream at a time.
const CHUNK: usize = 16 * 1024;

/// One entry of an mbox stream.
pub(super) enum Entry {
	/// The bytes of the entry, with the CRLF the separator line ends with
	/// still in them: the delivered message does not carry them.
	Bytes(Vec<u8>),
	/// The entry went past the limit: it was refused, and the rest of it
	/// was read and dropped.
	TooBig,
}

/// Where a line of the stream ends.
enum LineEnd {
	/// The line ends at this index of the pending bytes; the newline is
	/// there.
	At(usize),
	/// The line went past the limit: its bytes were dropped and the reader
	/// stands at the start of the next line.
	TooLong,
	/// The stream ended. The pending bytes, if any, are the last line and
	/// it has no terminator.
	End,
}

/// The bytes of an mbox stream that were read and not consumed yet.
pub(super) struct Stream<R: Read> {
	reader: R,
	/// The bytes read and not consumed.
	buffer: Vec<u8>,
	/// Where the unconsumed bytes start.
	start: usize,
	/// The scratch the reads land in.
	chunk: Vec<u8>,
	/// Whether the stream is exhausted.
	eof: bool,
}

impl<R: Read> Stream<R> {
	/// A stream over `reader`.
	pub(super) fn new(reader: R) -> Self {
		Self {
			reader,
			buffer: Vec::new(),
			start: 0,
			chunk: vec![0u8; CHUNK],
			eof: false,
		}
	}

	/// The bytes that were read and not consumed.
	fn pending(&self) -> &[u8] {
		&self.buffer[self.start..]
	}

	/// Drop the first `count` pending bytes.
	fn consume(&mut self, count: usize) {
		self.start += count;
	}

	/// Drop every pending byte.
	fn discard(&mut self) {
		self.start = self.buffer.len();
	}

	/// Read more bytes into the buffer, never past `limit` bytes.
	fn fill(&mut self, limit: usize) -> std::io::Result<()> {
		if self.start > 0 {
			self.buffer.drain(..self.start);
			self.start = 0;
		}
		let room = limit.saturating_sub(self.buffer.len());
		if room == 0 {
			return Ok(());
		}
		let want = room.min(self.chunk.len());
		let read = self.reader.read(&mut self.chunk[..want])?;
		if read == 0 {
			self.eof = true;
		} else {
			self.buffer.extend_from_slice(&self.chunk[..read]);
		}
		Ok(())
	}

	/// Where the next line ends.
	fn line(&mut self, limit: usize) -> std::io::Result<LineEnd> {
		loop {
			let index = self.pending().iter().position(|&byte| byte == b'\n');
			if let Some(index) = index {
				return Ok(LineEnd::At(index));
			}
			if self.eof {
				return Ok(LineEnd::End);
			}
			if self.pending().len() >= limit {
				// The line is longer than the limit: drop it and read on
				// to the next one.
				self.skip_line(limit)?;
				return Ok(LineEnd::TooLong);
			}
			self.fill(limit)?;
		}
	}

	/// Read and drop the rest of the current line.
	fn skip_line(&mut self, limit: usize) -> std::io::Result<()> {
		loop {
			let index = self.pending().iter().position(|&byte| byte == b'\n');
			if let Some(index) = index {
				self.consume(index + 1);
				return Ok(());
			}
			self.discard();
			if self.eof {
				return Ok(());
			}
			self.fill(limit)?;
		}
	}
}

/// The next entry of the stream, or `None` at its end.
pub(super) fn next_entry<R: Read>(
	stream: &mut Stream<R>,
	limit: usize,
) -> std::io::Result<Option<Entry>> {
	if !skip_to_entry(stream, limit)? {
		return Ok(None);
	}
	let mut body: Vec<u8> = Vec::new();
	// The entry may take two bytes more than the limit: the CRLF the
	// separator line ends with is not part of the message, so the message
	// the entry carries is two bytes shorter than the entry.
	let cap = limit.saturating_add(2);
	let mut too_big = false;
	loop {
		match stream.line(limit)? {
			LineEnd::End => {
				// The last line of the stream, with no terminator.
				let end = stream.pending().len();
				if end > 0 && !too_big {
					too_big = !add_line(&mut body, &stream.pending()[..end], cap);
				}
				break;
			}
			LineEnd::TooLong => {
				// The line does not fit the limit: the entry cannot either.
				too_big = true;
			}
			LineEnd::At(end) => {
				if stream.pending().starts_with(b"From ") {
					// A new entry begins: this one ends here. The line
					// is left for the next entry, which starts with it.
					break;
				}
				if !too_big {
					too_big = !add_line(&mut body, &stream.pending()[..end], cap);
				}
				stream.consume(end + 1);
			}
		}
	}
	Ok(Some(if too_big {
		Entry::TooBig
	} else {
		Entry::Bytes(body)
	}))
}

/// Read up to the `From ` line that starts the next entry. Returns false
/// when the stream holds no more entries.
fn skip_to_entry<R: Read>(stream: &mut Stream<R>, limit: usize) -> std::io::Result<bool> {
	loop {
		match stream.line(limit)? {
			LineEnd::End => return Ok(false),
			LineEnd::TooLong => {}
			LineEnd::At(end) => {
				let separator = stream.pending().starts_with(b"From ");
				stream.consume(end + 1);
				if separator {
					return Ok(true);
				}
			}
		}
	}
}

/// Add one line of an entry to its bytes. Returns false when the entry goes
/// past the cap, and then nothing of the line was added.
fn add_line(body: &mut Vec<u8>, line: &[u8], cap: usize) -> bool {
	// A line of a CRLF stream ends with the CR its terminator brought; the
	// message carries CRLF, so it is dropped here.
	let line = line.strip_suffix(b"\r").unwrap_or(line);
	// Undo mboxrd quoting: a `>*From ` line loses one leading `>`.
	let quoted = usize::from(
		line.starts_with(b">") && {
			let rest = &line[1..];
			let depth = rest.iter().take_while(|&&byte| byte == b'>').count();
			rest[depth..].starts_with(b"From ")
		},
	);
	// Drop the `X-Mailbox` header our own export prepends (entry start).
	let marker = body.is_empty() && line.starts_with(b"X-Mailbox:");
	let size = body
		.len()
		.saturating_add(line.len() - quoted)
		.saturating_add(2);
	if !marker && size > cap {
		return false;
	}
	if !marker {
		body.extend_from_slice(&line[quoted..]);
		body.extend_from_slice(b"\r\n");
	}
	true
}
