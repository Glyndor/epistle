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
