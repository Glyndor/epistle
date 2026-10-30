//! Reading a day file a line at a time, never holding more than one line.
//!
//! A line longer than [`MAX_LINE`] is not one this server wrote: it is
//! reported and skipped without reading it into memory. A last line with no
//! newline is a write that never completed.

use std::io::{BufRead, Read};

use super::record::MAX_LINE;

/// One line of a day file.
#[derive(Debug, PartialEq, Eq)]
pub enum Line<'a> {
	/// A complete line, without its newline.
	Complete(&'a [u8]),
	/// A line longer than [`MAX_LINE`]; its bytes were skipped.
	TooLong,
	/// The last line of the file, with no newline: an interrupted write.
	Torn(&'a [u8]),
}

/// A line reader over a day file.
pub struct Lines<R> {
	reader: R,
	line: Vec<u8>,
	number: u64,
}

impl<R: BufRead> Lines<R> {
	/// Read lines from `reader`.
	pub fn new(reader: R) -> Self {
		Lines {
			reader,
			line: Vec::new(),
			number: 0,
		}
	}

	/// The next line and its 1-based number, or `None` at the end of the
	/// file.
	pub fn next_line(&mut self) -> std::io::Result<Option<(u64, Line<'_>)>> {
		self.line.clear();
		// One byte past the limit tells a line at the limit from a longer one.
		let read = (&mut self.reader)
			.take(MAX_LINE as u64 + 2)
			.read_until(b'\n', &mut self.line)?;
		if read == 0 {
			return Ok(None);
		}
		self.number += 1;
		if self.line.last() == Some(&b'\n') {
			self.line.pop();
			if self.line.len() > MAX_LINE {
				return Ok(Some((self.number, Line::TooLong)));
			}
			return Ok(Some((self.number, Line::Complete(&self.line))));
		}
		if self.line.len() > MAX_LINE {
			drain_line(&mut self.reader)?;
			return Ok(Some((self.number, Line::TooLong)));
		}
		Ok(Some((self.number, Line::Torn(&self.line))))
	}
}

/// Read and drop the rest of a line, a buffer at a time.
fn drain_line(reader: &mut impl BufRead) -> std::io::Result<()> {
	loop {
		let buffer = reader.fill_buf()?;
		if buffer.is_empty() {
			return Ok(());
		}
		match buffer.iter().position(|byte| *byte == b'\n') {
			Some(at) => {
				reader.consume(at + 1);
				return Ok(());
			}
			None => {
				let length = buffer.len();
				reader.consume(length);
			}
		}
	}
}

#[cfg(test)]
mod tests;
