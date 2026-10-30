//! The decoder resumes its scan where the previous call stopped.

use super::*;

/// Feed `input` in pieces of `step` bytes, asking for lines after each one.
fn decode_in_steps(input: &[u8], step: usize, limit: usize) -> Result<Vec<Vec<u8>>, LineError> {
	let mut decoder = LineDecoder::with_limit(limit);
	let mut lines = Vec::new();
	for piece in input.chunks(step) {
		decoder.feed(piece);
		while let Some(line) = decoder.next_line()? {
			lines.push(line);
		}
	}
	Ok(lines)
}

#[test]
fn split_input_gives_the_same_lines_and_errors() {
	let cases: [&[u8]; 6] = [
		b"a1 NOOP\r\nb2 CAPABILITY\r\n\r\n",
		b"abc\r\ndef\rx\r\n",
		b"abc\r\nde\nf\r\n",
		b"abc\r\nd\0ef\r\n",
		b"abc\r",
		b"\r\n\r\nxyz",
	];
	for input in cases {
		let whole = decode_in_steps(input, input.len(), MAX_LINE_LENGTH);
		for step in 1..input.len() {
			assert_eq!(
				decode_in_steps(input, step, MAX_LINE_LENGTH),
				whole,
				"{input:?} in steps of {step}"
			);
		}
	}
}

#[test]
fn errors_found_after_a_resume() {
	assert_eq!(
		decode_in_steps(b"abcd\nx", 2, 64),
		Err(LineError::BareControlCharacter)
	);
	assert_eq!(
		decode_in_steps(b"abc\rd", 1, 64),
		Err(LineError::BareControlCharacter)
	);
	assert_eq!(decode_in_steps(b"abcd\0x", 3, 64), Err(LineError::NulByte));
	assert_eq!(decode_in_steps(&[b'a'; 70], 1, 64), Err(LineError::TooLong));
}

#[test]
fn taking_literal_bytes_rescans_what_follows() {
	let mut decoder = LineDecoder::new();
	decoder.feed(b"xyz");
	assert_eq!(decoder.next_line(), Ok(None));
	assert_eq!(decoder.take_buffered(3), b"xyz");
	decoder.feed(b"ok\r\n");
	assert_eq!(decoder.next_line(), Ok(Some(b"ok".to_vec())));
	decoder.feed(b"lit\r\nnext\r\n");
	assert_eq!(decoder.discard_buffered(5), 5);
	assert_eq!(decoder.next_line(), Ok(Some(b"next".to_vec())));
}

#[test]
fn a_long_line_sent_byte_by_byte_is_linear() {
	// A rescan from the start on every call would compare about 2e9 bytes
	// for this 64 KiB line; resuming compares each byte once.
	const LIMIT: usize = 64 * 1024;
	let mut line = vec![b'a'; LIMIT];
	line.extend_from_slice(b"\r\n");
	let started = std::time::Instant::now();
	let lines = decode_in_steps(&line, 1, LIMIT).expect("decodes");
	assert_eq!(lines.len(), 1);
	assert_eq!(lines[0].len(), LIMIT);
	assert!(
		started.elapsed() < std::time::Duration::from_secs(1),
		"{:?}",
		started.elapsed()
	);
}

#[test]
fn the_scan_offset_follows_the_buffer() {
	let mut decoder = LineDecoder::with_limit(4096);
	for _ in 0..1000 {
		decoder.feed(b"a");
		assert_eq!(decoder.next_line(), Ok(None));
	}
	assert_eq!(decoder.scanned, 1000);
	decoder.feed(b"\r");
	assert_eq!(decoder.next_line(), Ok(None));
	assert_eq!(decoder.scanned, 1000, "a trailing CR is looked at again");
	decoder.feed(b"\n");
	assert!(decoder.next_line().expect("line").is_some());
	assert_eq!(decoder.scanned, 0);
}
