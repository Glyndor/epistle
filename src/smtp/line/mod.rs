//! Strict CRLF line framing for SMTP streams.
//!
//! RFC 5321 requires CRLF line endings. Accepting bare LF or bare CR is the
//! root of SMTP smuggling, so this decoder rejects both outright: a bare CR
//! or LF anywhere in the stream is a protocol error, never silently fixed.

/// Maximum data line length accepted, excluding CRLF (RFC 5321 says 998).
pub const MAX_LINE_LENGTH: usize = 998;

/// Errors produced while decoding lines from the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
	/// A CR not followed by LF, or an LF not preceded by CR.
	BareControlCharacter,
	/// Line longer than the decoder's limit (`MAX_LINE_LENGTH` by default).
	TooLong,
	/// Line contains a NUL byte.
	NulByte,
}

/// What [`LineCheck::step`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
	/// The byte belongs to a line that is not finished.
	More,
	/// The byte was the LF of a CRLF: the line before it is complete.
	EndOfLine,
}

/// The per-byte rules of strict CRLF framing, shared by [`LineDecoder`]
/// (DATA and commands) and by the BDAT body check, so that one stream of
/// octets gets the same verdict whichever way it arrives. It keeps only the
/// state between two bytes, so a body can be fed to it in pieces cut
/// anywhere, a CR and its LF in different ones included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineCheck {
	/// Octets of the current line seen so far, a pending CR not counted.
	len: usize,
	/// The last byte was a CR still waiting for its LF.
	cr: bool,
	/// Count a leading dot as two octets, the way the same line is counted
	/// once a sender has dot-stuffed it (see [`Self::stored`]).
	escape_dot: bool,
}

impl LineCheck {
	/// A check at the start of a line.
	pub fn new() -> Self {
		Self::default()
	}

	/// A check on message octets as they are stored, not as they cross a
	/// DATA wire. DATA caps a line with its stuffing dot, so a stored line
	/// that begins with a dot is held one octet shorter: it grows by that dot
	/// when it is sent on, and BDAT must refuse what DATA refuses.
	pub fn stored() -> Self {
		Self {
			escape_dot: true,
			..Self::default()
		}
	}

	/// A check that has already seen `len` octets of a line, none of them
	/// CR, LF or NUL.
	fn resume(len: usize) -> Self {
		Self {
			len,
			cr: false,
			escape_dot: false,
		}
	}

	/// Octets of the current line seen so far, a pending CR not counted.
	fn len(&self) -> usize {
		self.len
	}

	/// Take one more byte of a line capped at `max_line` octets (CRLF not
	/// counted).
	pub fn step(&mut self, byte: u8, max_line: usize) -> Result<Step, LineError> {
		if self.cr {
			if byte != b'\n' {
				return Err(LineError::BareControlCharacter);
			}
			let len = std::mem::take(&mut self.len);
			self.cr = false;
			return if len > max_line {
				Err(LineError::TooLong)
			} else {
				Ok(Step::EndOfLine)
			};
		}
		match byte {
			0 => Err(LineError::NulByte),
			b'\n' => Err(LineError::BareControlCharacter),
			b'\r' => {
				self.cr = true;
				Ok(Step::More)
			}
			_ => {
				self.len += if self.escape_dot && self.len == 0 && byte == b'.' {
					2
				} else {
					1
				};
				Ok(Step::More)
			}
		}
	}

	/// Take a run of bytes, for a caller that does not need the line ends.
	/// Stops at the first violation. A line that is still open when the run
	/// ends and is already past the cap is refused here too, so a stream with
	/// no line end in it cannot grow without bound.
	pub fn feed(&mut self, bytes: &[u8], max_line: usize) -> Result<(), LineError> {
		for &byte in bytes {
			self.step(byte, max_line)?;
		}
		self.check_open(max_line)
	}

	/// Refuse a line that is still open and already longer than `max_line`
	/// (a CR may follow the cap, so one octet more is still waiting).
	fn check_open(&self, max_line: usize) -> Result<(), LineError> {
		if self.len + usize::from(self.cr) > max_line + 1 {
			return Err(LineError::TooLong);
		}
		Ok(())
	}

	/// The stream ended: a CR still waiting for its LF is a bare CR, and a
	/// last line left open past `max_line` is too long (the sender will end
	/// it with a CRLF of its own).
	pub fn finish(&self, max_line: usize) -> Result<(), LineError> {
		if self.cr {
			return Err(LineError::BareControlCharacter);
		}
		if self.len > max_line {
			return Err(LineError::TooLong);
		}
		Ok(())
	}
}

/// Incremental CRLF line decoder over received bytes.
#[derive(Debug)]
pub struct LineDecoder {
	buffer: Vec<u8>,
	max_line: usize,
	/// Bytes at the front of `buffer` already checked by [`Self::next_line`]
	/// and found to hold no CR, LF or NUL. Resuming there keeps the work per
	/// line linear when a client sends it in many small pieces.
	scanned: usize,
}

impl Default for LineDecoder {
	fn default() -> Self {
		Self::with_limit(MAX_LINE_LENGTH)
	}
}

impl LineDecoder {
	/// Create an empty decoder with the SMTP line limit.
	pub fn new() -> Self {
		Self::default()
	}

	/// Create an empty decoder that accepts lines of up to `max_line` octets
	/// (excluding CRLF), for protocols whose commands are longer than SMTP's.
	pub fn with_limit(max_line: usize) -> Self {
		Self {
			buffer: Vec::new(),
			max_line,
			scanned: 0,
		}
	}

	/// Append received bytes to the internal buffer.
	pub fn feed(&mut self, bytes: &[u8]) {
		self.buffer.extend_from_slice(bytes);
	}

	/// Drain up to `max` already-buffered bytes (for literal payloads that
	/// arrived in the same read as their command line).
	pub fn take_buffered(&mut self, max: usize) -> Vec<u8> {
		let take = self.buffer.len().min(max);
		self.scanned = 0;
		self.buffer.drain(..take).collect()
	}

	/// Discard up to `max` buffered literal bytes without allocating storage
	/// for them. Any following command stays in the decoder.
	pub fn discard_buffered(&mut self, max: usize) -> usize {
		let take = self.buffer.len().min(max);
		self.scanned = 0;
		self.buffer.drain(..take);
		take
	}

	#[cfg(test)]
	pub(crate) fn buffer_capacity(&self) -> usize {
		self.buffer.capacity()
	}

	/// Try to extract the next complete line (without CRLF). Returns
	/// `Ok(None)` when more bytes are needed.
	pub fn next_line(&mut self) -> Result<Option<Vec<u8>>, LineError> {
		let mut check = LineCheck::resume(self.scanned);
		for i in self.scanned..self.buffer.len() {
			if check.step(self.buffer[i], self.max_line)? == Step::EndOfLine {
				// `i` is the LF: the line ends before the CR.
				let line = self.buffer[..i - 1].to_vec();
				self.buffer.drain(..=i);
				self.scanned = 0;
				return Ok(Some(line));
			}
		}
		// A CR that is the last byte so far waits for more input, and is
		// looked at again then.
		self.scanned = check.len();
		check.check_open(self.max_line)?;
		Ok(None)
	}
}

/// `len` octets of CRLF-framed filler (a header and the empty line after it,
/// then lines of 70 octets), for tests that need message data of a given
/// size. It never ends on a CR, so pieces of it can follow one another.
#[cfg(test)]
pub(crate) fn filler(len: usize) -> Vec<u8> {
	let line = b"x".repeat(70).into_iter().chain(*b"\r\n");
	let mut data: Vec<u8> = b"S: x\r\n\r\n"
		.iter()
		.copied()
		.chain(line.cycle())
		.take(len)
		.collect();
	if data.last() == Some(&b'\r') {
		data[len - 1] = b'x';
	}
	data
}

#[cfg(test)]
mod tests;
