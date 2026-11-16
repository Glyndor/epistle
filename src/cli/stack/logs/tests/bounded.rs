//! A line with no end must not be held whole, whatever the container prints.

use std::io::{BufReader, Cursor, Read};

use super::super::merge::merge_readers;
use super::super::{LINE_BYTES, next_line};

/// `total` bytes of `x` with no newline, then `tail`, counting what was read.
struct Endless {
	left: usize,
	tail: Cursor<Vec<u8>>,
}

impl Endless {
	fn new(total: usize, tail: &str) -> Self {
		Self {
			left: total,
			tail: Cursor::new(tail.as_bytes().to_vec()),
		}
	}
}

impl Read for Endless {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		if self.left > 0 {
			let count = self.left.min(buf.len());
			buf[..count].fill(b'x');
			self.left -= count;
			return Ok(count);
		}
		self.tail.read(buf)
	}
}

const MIB: usize = 1024 * 1024;

#[test]
fn a_line_of_several_mib_is_held_up_to_the_cap_and_the_rest_is_counted() {
	let mut reader = BufReader::with_capacity(4096, Endless::new(5 * MIB, "\nnext\n"));
	let line = next_line(&mut reader, LINE_BYTES, false).unwrap().unwrap();
	assert_eq!(line.bytes.len(), LINE_BYTES);
	assert!(
		line.bytes.capacity() <= 4 * LINE_BYTES,
		"{}",
		line.bytes.capacity()
	);
	assert_eq!(line.omitted, (5 * MIB - LINE_BYTES) as u64);
	assert!(!line.pending);
	let after = next_line(&mut reader, LINE_BYTES, false).unwrap().unwrap();
	assert_eq!(after.bytes, b"next");
	assert!(next_line(&mut reader, LINE_BYTES, false).unwrap().is_none());
}

#[test]
fn a_giant_line_without_a_newline_ends_with_the_input() {
	let mut reader = BufReader::new(Endless::new(3 * MIB, ""));
	let line = next_line(&mut reader, LINE_BYTES, false).unwrap().unwrap();
	assert_eq!(line.bytes.len(), LINE_BYTES);
	assert_eq!(line.omitted, (3 * MIB - LINE_BYTES) as u64);
	assert!(next_line(&mut reader, LINE_BYTES, false).unwrap().is_none());
}

#[test]
fn a_line_of_exactly_the_cap_loses_nothing() {
	let text = format!("{}\nz\n", "q".repeat(LINE_BYTES));
	let mut reader = Cursor::new(text.into_bytes());
	let line = next_line(&mut reader, LINE_BYTES, false).unwrap().unwrap();
	assert_eq!((line.bytes.len(), line.omitted), (LINE_BYTES, 0));
	assert_eq!(
		next_line(&mut reader, LINE_BYTES, false)
			.unwrap()
			.unwrap()
			.bytes,
		b"z"
	);
}

#[test]
fn a_cut_giant_line_leaves_the_lines_after_it_whole() {
	let giant = format!("a-1 | 2026-01-01T10:00:01Z {}\n", "g".repeat(3 * MIB));
	let normal = "a-1 | 2026-01-01T10:00:02Z after\n";
	let other = "b-1 | 2026-01-01T10:00:03Z other\n";
	let readers = vec![
		Cursor::new(format!("{giant}{normal}").into_bytes()),
		Cursor::new(other.as_bytes().to_vec()),
	];
	let mut out = Vec::new();
	merge_readers(readers, true, &mut out).unwrap();
	let text = String::from_utf8(out).unwrap();
	let lines: Vec<&str> = text.lines().collect();
	assert_eq!(lines.len(), 3);
	assert!(lines[0].ends_with(&format!(
		" [{} more bytes cut; --raw shows them]",
		3 * MIB - 500
	)));
	assert!(lines[0].len() < 700);
	assert_eq!(lines[1], normal.trim_end());
	assert_eq!(lines[2], other.trim_end());
}

#[test]
fn raw_hands_over_the_whole_line_without_holding_it() {
	let giant = format!("a-1 | 2026-01-01T10:00:01Z {}\n", "g".repeat(3 * MIB));
	let normal = "b-1 | 2026-01-01T10:00:02Z after\n";
	let mut reader = Cursor::new(giant.clone().into_bytes());
	let held = next_line(&mut reader, LINE_BYTES, true).unwrap().unwrap();
	assert!(held.pending);
	assert_eq!(held.bytes.len(), LINE_BYTES);
	let readers = vec![
		Cursor::new(giant.clone().into_bytes()),
		Cursor::new(normal.as_bytes().to_vec()),
	];
	let mut out = Vec::new();
	merge_readers(readers, false, &mut out).unwrap();
	assert_eq!(String::from_utf8(out).unwrap(), format!("{giant}{normal}"));
}

#[test]
fn raw_keeps_a_multibyte_character_split_at_the_cap() {
	let text = format!("{}é\nend\n", "a".repeat(LINE_BYTES - 1));
	let mut out = Vec::new();
	merge_readers(
		vec![Cursor::new(text.clone().into_bytes())],
		false,
		&mut out,
	)
	.unwrap();
	assert_eq!(String::from_utf8(out).unwrap(), text);
}
