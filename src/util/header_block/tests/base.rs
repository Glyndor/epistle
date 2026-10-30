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
