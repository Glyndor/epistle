//! The bytes of a POP3 response, in pieces of bounded size.

use super::session::Response;

/// Octets of message body taken into one piece.
pub const WIRE_CHUNK: usize = 64 * 1024;

/// An iterator over the pieces of one encoded [`Response`]. The body of a
/// multiline response is dot-stuffed a chunk at a time, so the encoding
/// holds at most one chunk beyond the response itself.
pub struct Wire<'a> {
	response: &'a Response,
	started: bool,
	done: bool,
	position: usize,
	at_line_start: bool,
	previous: u8,
}

impl<'a> Wire<'a> {
	pub(super) fn new(response: &'a Response) -> Self {
		Wire {
			response,
			started: false,
			done: false,
			position: 0,
			at_line_start: true,
			previous: 0,
		}
	}

	/// Byte-stuff `chunk` onto `out`: any line starting with `.` gets an
	/// extra `.`, and bare LF is normalized to CRLF so the terminator is
	/// unambiguous.
	fn stuff(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
		for &byte in chunk {
			if self.at_line_start && byte == b'.' {
				out.push(b'.');
			}
			if byte == b'\n' && self.previous != b'\r' {
				out.push(b'\r');
			}
			out.push(byte);
			self.at_line_start = byte == b'\n';
			self.previous = byte;
		}
	}
}

impl Iterator for Wire<'_> {
	type Item = Vec<u8>;

	fn next(&mut self) -> Option<Vec<u8>> {
		if self.done {
			return None;
		}
		let (status, body) = match self.response {
			Response::Continuation => {
				self.done = true;
				return Some(b"+ \r\n".to_vec());
			}
			Response::Ok(text) | Response::Bye(text) => {
				self.done = true;
				return Some(format!("+OK {text}\r\n").into_bytes());
			}
			Response::Err(text) => {
				self.done = true;
				return Some(format!("-ERR {text}\r\n").into_bytes());
			}
			Response::Multiline { status, body } => (status, body),
		};
		let mut out = Vec::new();
		if !self.started {
			self.started = true;
			out.extend_from_slice(format!("+OK {status}\r\n").as_bytes());
		}
		let end = (self.position + WIRE_CHUNK).min(body.len());
		out.reserve(end - self.position + 16);
		self.stuff(&body[self.position..end], &mut out);
		self.position = end;
		if end == body.len() {
			if !body.is_empty() && self.previous != b'\n' {
				if self.previous != b'\r' {
					out.push(b'\r');
				}
				out.push(b'\n');
			}
			out.extend_from_slice(b".\r\n");
			self.done = true;
		}
		Some(out)
	}
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
