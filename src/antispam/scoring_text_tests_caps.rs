//! The caps on the structure the walk follows: how deep and how many parts a
//! message may have and still be read part by part, what happens one past
//! them, and that the walk costs the same per byte at the caps as below them.

use super::*;
use crate::antispam::attachments::walk::STEPS;
use crate::antispam::bayes::tokenize;

/// The caps the owner decided, written out so that moving the constants breaks
/// these tests instead of moving them along.
const DEPTH: usize = 32;
const PARTS: usize = 10_000;

fn has(reduced: &ScoringText, word: &str) -> bool {
	tokenize(&reduced.text).iter().any(|t| t == word)
}

fn base64_of(bytes: &[u8]) -> String {
	use base64::Engine as _;
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The last part of every message here: text in base64, which is only read
/// if the walk gets to it and decodes it.
fn hidden_leaf() -> String {
	format!(
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
		base64_of(b"hiddenword")
	)
}

/// `levels` multiparts inside one another, each opening one part that holds
/// the next, the hidden text at the bottom, then `tail`. The boundaries share
/// a long prefix, so a line that starts like one costs a comparison with each.
fn nested(levels: usize, tail: &[u8]) -> Vec<u8> {
	let prefix = "p".repeat(58);
	let mut raw = String::from("Subject: x\r\n");
	for level in 0..levels {
		raw.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"{prefix}{level:03}\"\r\n\r\n--{prefix}{level:03}\r\n"
		));
	}
	raw.push_str(&hidden_leaf());
	let mut raw = raw.into_bytes();
	raw.extend_from_slice(tail);
	raw
}

/// One multipart of `children` empty parts and then the hidden text, so the
/// message has `children + 2` parts counting the container and the text.
fn flat(children: usize) -> Vec<u8> {
	let mut raw = String::from("Subject: x\r\nContent-Type: multipart/mixed; boundary=bb\r\n\r\n");
	raw.push_str(&"--bb\r\n\r\n\r\n".repeat(children));
	raw.push_str(&format!("--bb\r\n{}--bb--\r\n", hidden_leaf()));
	raw.into_bytes()
}

/// A line that starts like the boundary of every open multipart and is none.
fn near_delimiters(bytes: usize) -> Vec<u8> {
	let line = format!("--{}zzz\r\n", "p".repeat(58));
	line.repeat(bytes / line.len()).into_bytes()
}

/// The bytes the walk examined reducing `raw`.
fn steps_of(raw: &[u8]) -> u64 {
	STEPS.with(|steps| steps.set(0));
	scoring_text(raw);
	STEPS.with(|steps| steps.get())
}

#[test]
fn the_deepest_nesting_followed_is_read_whole() {
	let reduced = scoring_text(&nested(DEPTH, b""));
	assert!(
		has(&reduced, "hiddenword"),
		"the text at the bottom is read"
	);
	assert!(!reduced.clipped && !reduced.unread);
}

#[test]
fn one_level_past_the_cap_is_read_as_bytes_and_clipped() {
	let reduced = scoring_text(&nested(DEPTH + 1, b""));
	assert!(reduced.clipped, "not read in full: scored at the floor");
	assert!(!reduced.unread, "it was read, as bytes");
	assert!(
		!has(&reduced, "hiddenword"),
		"base64 is not decoded as bytes"
	);
}

#[test]
fn the_most_parts_followed_are_read_whole() {
	// The container counts as a part, and so does the text at the end.
	let reduced = scoring_text(&flat(PARTS - 2));
	assert!(has(&reduced, "hiddenword"));
	assert!(!reduced.clipped && !reduced.unread);
}

#[test]
fn one_part_past_the_cap_is_read_as_bytes_and_clipped() {
	let reduced = scoring_text(&flat(PARTS - 1));
	assert!(reduced.clipped && !reduced.unread);
	assert!(!has(&reduced, "hiddenword"));
}

/// The cost is counted in bytes the walk examines, not in seconds: at the
/// deepest nesting, with every line starting like a delimiter, doubling the
/// message doubles the work, and no byte is examined more than once for the
/// line and once for each open boundary.
#[test]
fn the_walk_costs_a_fixed_amount_per_byte_at_the_deepest_nesting() {
	let small = nested(DEPTH, &near_delimiters(1 << 20));
	let large = nested(DEPTH, &near_delimiters(2 << 20));
	let (one, two) = (steps_of(&small), steps_of(&large));
	assert!(
		one <= small.len() as u64 * (DEPTH as u64 + 1),
		"{one} steps for {} bytes",
		small.len()
	);
	let ratio = two as f64 / one as f64;
	assert!((1.9..2.1).contains(&ratio), "{one} then {two}: x{ratio:.2}");
}

/// A message past a cap is given up on where the count runs out:
/// the megabytes after it are not walked.
#[test]
fn a_walk_that_gives_up_on_parts_does_not_scan_what_follows() {
	let mut raw = flat(PARTS + 1);
	raw.extend_from_slice(&near_delimiters(4 << 20));
	let steps = steps_of(&raw);
	assert!(steps < 16 * PARTS as u64 + 4096, "{steps} steps");
	let raw = nested(DEPTH + 1, &near_delimiters(4 << 20));
	let steps = steps_of(&raw);
	assert!(steps < 16 * 1024, "{steps} steps");
}

/// The walk keeps its open boundaries in a vector, so the thread's stack
/// does not grow with the nesting: a very small one is enough.
#[test]
fn the_nesting_cap_does_not_depend_on_the_size_of_the_stack() {
	let raw = nested(DEPTH, &near_delimiters(1 << 16));
	let reduced = std::thread::Builder::new()
		.stack_size(192 * 1024)
		.spawn(move || scoring_text(&raw))
		.unwrap()
		.join()
		.unwrap();
	assert!(has(&reduced, "hiddenword") && !reduced.clipped && !reduced.unread);
}
