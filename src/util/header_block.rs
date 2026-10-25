//! Where the header block of a raw message ends and what its lines are, in
//! one place: the Sieve interpreter reads the headers by it, and the check
//! that refuses a message with thousands of header fields counts them by it,
//! so the two cannot disagree about what a header is.

/// A line without its terminator, which is `\n` or `\r\n`.
fn unterminated(line: &[u8]) -> &[u8] {
	let line = line.strip_suffix(b"\n").unwrap_or(line);
	line.strip_suffix(b"\r").unwrap_or(line)
}

/// The header block of `raw` and the body after it. The block ends at the
/// first `CRLF CRLF`, and without one the whole message is header and there
/// is no body.
///
/// That is the longest block any reader of a message takes: the ones that
/// also end it at a bare `LF LF`, at `LF CR`, or at a line of blanks (IMAP,
/// POP3 `TOP`, the trace headers) take a prefix of it, and the ones that
/// look only for `CRLF CRLF` take exactly this. A field count made over this
/// block is therefore never smaller than what any of them sees, so no field
/// can be hidden from the count by a terminator some reader honours and the
/// count does not. The price is that a message with bare `LF` line ends is
/// all header here, and one with more than the field limit of lines is
/// refused as having too many fields; it is the safe side.
pub fn split(raw: &[u8]) -> (&[u8], &[u8]) {
	match raw.windows(4).position(|w| w == b"\r\n\r\n") {
		Some(at) => (&raw[..at + 2], &raw[at + 4..]),
		None => (raw, &[]),
	}
}

/// The header block of `raw` and the body after it. The block ends at the
/// first empty line, whichever way that line is ended, and without one the
/// whole message is header and there is no body.
///
/// A message whose first line is empty has no header block at all: what
/// follows is body text, so a field a reader finds there is not a field of
/// the message. A reader that ends the block at `CRLF CRLF` alone takes a
/// longer block for an LF-only message, which is why the header readers of
/// the server use this one and not that one.
pub(crate) fn split_at_blank_line(raw: &[u8]) -> (&[u8], &[u8]) {
	let mut offset = 0;
	while offset < raw.len() {
		let end = raw[offset..]
			.iter()
			.position(|byte| *byte == b'\n')
			.map_or(raw.len(), |index| offset + index + 1);
		if unterminated(&raw[offset..end]).is_empty() {
			return (&raw[..offset], &raw[end..]);
		}
		offset = end;
	}
	(raw, &[])
}

/// The line ending the message is written with: the one of its first line,
/// and `CRLF` for a message with no line ending of its own.
pub(crate) fn line_ending(raw: &[u8]) -> &'static [u8] {
	match raw.iter().position(|byte| *byte == b'\n') {
		Some(index) if index > 0 && raw[index - 1] == b'\r' => b"\r\n",
		Some(_) => b"\n",
		None => b"\r\n",
	}
}

/// I borrow an SMTP-ready message, or normalize its LF and final line ending
/// before validation, signing and queueing so DATA cannot change those bytes.
pub(crate) fn outbound_crlf(data: &[u8]) -> std::borrow::Cow<'_, [u8]> {
	if data.ends_with(b"\r\n")
		&& data
			.iter()
			.enumerate()
			.all(|(index, byte)| *byte != b'\n' || (index > 0 && data[index - 1] == b'\r'))
	{
		return std::borrow::Cow::Borrowed(data);
	}
	let mut normalized = Vec::with_capacity(data.len());
	let mut previous = None;
	for byte in data.iter().copied() {
		if byte == b'\n' && previous != Some(b'\r') {
			normalized.push(b'\r');
		}
		normalized.push(byte);
		previous = Some(byte);
	}
	if !normalized.ends_with(b"\r\n") {
		normalized.extend_from_slice(b"\r\n");
	}
	std::borrow::Cow::Owned(normalized)
}

/// The lines of a header block, each without its terminator.
pub fn lines(block: &[u8]) -> impl Iterator<Item = &[u8]> {
	block.split_inclusive(|b| *b == b'\n').map(unterminated)
}

/// Whether `line` begins a header field: it is not empty and does not
/// continue the field before it (a folded line starts with a space or tab).
pub fn begins_field(line: &[u8]) -> bool {
	!line.is_empty() && !matches!(line.first(), Some(b' ' | b'\t'))
}

/// How many header fields `raw` has.
pub fn field_count(raw: &[u8]) -> usize {
	lines(split(raw).0)
		.filter(|line| begins_field(line))
		.count()
}

/// Messages whose header block ends in different ways, with fields after
/// the first terminator, for the tests of every reader of a header block.
#[cfg(test)]
pub(crate) mod cases {
	/// How many header fields a reader sees in `header_text`: the lines that
	/// begin a field, lines ending in `LF` or `CRLF`.
	pub(crate) fn fields_in(header_text: &[u8]) -> usize {
		super::lines(header_text)
			.filter(|line| super::begins_field(line))
			.count()
	}

	/// Raw messages: two fields, a terminator, then three more fields.
	pub(crate) fn messages() -> Vec<Vec<u8>> {
		let rest = "H1: x\r\nH2: y\r\nH3: z\r\n\r\nbody\r\n";
		[
			"\r\n\r\n",
			"\n\n",
			"\n\r\n",
			"\r\n\n",
			"\r\r",
			"\n \n",
			"\r\n \r\n",
			"\r\n\t\r\n",
			"\n\r",
			"\r\n\r\n\r\n",
			"\n\n\n\n",
		]
		.iter()
		.map(|end| format!("A: 1\r\nB: 2\r\n{end}{rest}").into_bytes())
		.chain([
			b"A: 1\nB: 2\r\n\r\nC: 3\n\nD: 4\r\n\r\nbody".to_vec(),
			b"A: 1\rB: 2\r\rC: 3\r\n\r\nbody".to_vec(),
			b"A: 1\nB: 2\nC: 3\nD: 4\n".to_vec(),
			b"".to_vec(),
		])
		.collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_block_ends_at_crlf_crlf_and_nowhere_else() {
		for (raw, header, body) in [
			(
				&b"A: 1\r\nB: 2\r\n\r\nbody"[..],
				&b"A: 1\r\nB: 2\r\n"[..],
				&b"body"[..],
			),
			(
				b"A: 1\nB: 2\n\nbody\nmore\n",
				b"A: 1\nB: 2\n\nbody\nmore\n",
				b"",
			),
			(b"A: 1\n\r\nbody", b"A: 1\n\r\nbody", b""),
			(b"A: 1\r\nB: 2", b"A: 1\r\nB: 2", b""),
			(b"", b"", b""),
		] {
			assert_eq!(split(raw), (header, body), "{raw:?}");
		}
	}

	#[test]
	fn folded_lines_are_not_fields() {
		assert_eq!(field_count(b"A: 1\r\n 2\r\n\t3\r\nB: 4\r\n\r\nC: x\r\n"), 2);
		assert_eq!(field_count(b"A: 1\nB: 2\n\n"), 2);
	}
}
