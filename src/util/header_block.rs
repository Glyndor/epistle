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
/// first empty line, whether the lines end in `\r\n` or in `\n`; without an
/// empty line the whole message is header and there is no body.
pub fn split(raw: &[u8]) -> (&[u8], &[u8]) {
	let mut start = 0;
	while start < raw.len() {
		let end = raw[start..]
			.iter()
			.position(|b| *b == b'\n')
			.map_or(raw.len(), |at| start + at);
		let next = (end + 1).min(raw.len());
		if unterminated(&raw[start..end]).is_empty() {
			return (&raw[..start], &raw[next..]);
		}
		start = next;
	}
	(raw, &[])
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_block_ends_at_the_first_empty_line_whatever_the_line_ends() {
		for (raw, header, body) in [
			(
				&b"A: 1\r\nB: 2\r\n\r\nbody"[..],
				&b"A: 1\r\nB: 2\r\n"[..],
				&b"body"[..],
			),
			(
				b"A: 1\nB: 2\n\nbody\nmore\n",
				b"A: 1\nB: 2\n",
				b"body\nmore\n",
			),
			(b"A: 1\n\r\nbody", b"A: 1\n", b"body"),
			(b"A: 1\r\n\nbody", b"A: 1\r\n", b"body"),
			(b"A: 1\r\nB: 2", b"A: 1\r\nB: 2", b""),
			(b"\r\nbody", b"", b"body"),
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
