//! The header block of a queued message, for a caller that asks to see it.
//! The body is never read past the blank line that ends the headers.

use serde::Serialize;

/// Most header fields returned for one message.
pub const MAX_HEADERS: usize = 200;
/// Most bytes of the header block that are read.
const MAX_BLOCK: usize = 64 * 1024;
/// Longest value returned for one field; a longer one is cut.
const MAX_VALUE: usize = 1000;

/// One header field: its name and its value with the folding undone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Header {
	/// The field name as the message spells it.
	pub name: String,
	/// The value, folded lines joined with one space, cut at 1000 characters.
	pub value: String,
}

/// The header fields of `message`, in order, up to [`MAX_HEADERS`], and
/// whether there were more (or the block was longer than was read).
pub fn headers_of(message: &[u8]) -> (Vec<Header>, bool) {
	let end = block_end(message);
	let mut truncated = end.1;
	let text = String::from_utf8_lossy(&message[..end.0]);
	let mut headers: Vec<Header> = Vec::new();
	for line in text.split('\n') {
		let line = line.strip_suffix('\r').unwrap_or(line);
		if line.starts_with([' ', '\t']) {
			if let Some(last) = headers.last_mut() {
				last.value.push(' ');
				last.value.push_str(line.trim());
			}
			continue;
		}
		let Some((name, value)) = line.split_once(':') else {
			continue;
		};
		if headers.len() == MAX_HEADERS {
			truncated = true;
			break;
		}
		headers.push(Header {
			name: name.trim().to_string(),
			value: value.trim().to_string(),
		});
	}
	for header in &mut headers {
		if header.value.chars().count() > MAX_VALUE {
			header.value = header.value.chars().take(MAX_VALUE).collect();
			truncated = true;
		}
	}
	(headers, truncated)
}

/// Where the header block of `message` ends, and whether it was cut at
/// [`MAX_BLOCK`] before a blank line.
fn block_end(message: &[u8]) -> (usize, bool) {
	let window = &message[..message.len().min(MAX_BLOCK)];
	// A message that begins with its blank line has no header fields.
	if window.starts_with(b"\r\n") || window.starts_with(b"\n") {
		return (0, false);
	}
	let blank = window
		.windows(4)
		.position(|four| four == b"\r\n\r\n")
		.map(|at| at + 2)
		.into_iter()
		.chain(
			window
				.windows(2)
				.position(|two| two == b"\n\n")
				.map(|at| at + 1),
		)
		.min();
	match blank {
		Some(at) => (at, false),
		None => (window.len(), message.len() > MAX_BLOCK),
	}
}
