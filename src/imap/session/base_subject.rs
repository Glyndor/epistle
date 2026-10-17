//! The RFC 5256 §2.1 base subject, the SUBJECT key of SORT and the grouping
//! key of THREAD=ORDEREDSUBJECT.
//!
//! The Subject is client-controlled and SORT reads it for every message, so
//! the extraction runs in time linear in the subject: the steps move a start
//! and an end offset over one buffer instead of editing a string, every
//! bracket and space lookup is answered from tables built once, and a step
//! either consumes input or ends the loop it is in.

use crate::util::encoded_word;

/// How much of the decoded subject is looked at. RFC 5322 §2.1.1 limits a
/// line to 998 characters and real subjects are far shorter, so for real
/// mail the bound never cuts anything. A longer subject still sorts by its
/// first 8 KiB, so only two subjects that agree on all of them can compare
/// differently than they would in full, and those then tie and fall back to
/// the sequence number.
const MAX_SUBJECT: usize = 8 * 1024;

/// The base subject of a raw Subject header value, uppercased for the
/// i;ascii-casemap comparison both commands use.
pub(super) fn base_subject(raw: &str) -> String {
	base_subject_and_reply(raw).0
}

/// The base subject of a raw Subject header value, and whether extracting
/// it removed a `re:`/`fw:`/`fwd:` leader, a `(fwd)` trailer or a
/// `[fwd: ...]` wrapper: the RFC 5256 §3 test for a reply or forward that
/// THREAD=REFERENCES uses when it merges threads by subject.
pub(super) fn base_subject_and_reply(raw: &str) -> (String, bool) {
	// (1) Decode encoded words and collapse every run of whitespace.
	let mut decoded = encoded_word::decode(raw);
	if decoded.len() > MAX_SUBJECT {
		let mut cut = MAX_SUBJECT;
		while !decoded.is_char_boundary(cut) {
			cut -= 1;
		}
		decoded.truncate(cut);
	}
	let text = decoded
		.split([' ', '\t', '\r', '\n'])
		.filter(|word| !word.is_empty())
		.collect::<Vec<_>>()
		.join(" ");
	extract_flagged(&text)
}

/// The subject half of [`extract_flagged`].
#[cfg(test)]
fn extract(text: &str) -> String {
	extract_flagged(text).0
}

/// Steps (2) to (6) on a decoded subject whose whitespace is collapsed, and
/// whether a step removed a reply or forward marker.
fn extract_flagged(text: &str) -> (String, bool) {
	let scan = Scan::new(text.as_bytes());
	let (mut start, mut end) = (0, text.len());
	let mut reply = false;
	loop {
		let trimmed = scan.strip_trailers(start, end);
		reply |= trimmed.1;
		end = trimmed.0;
		let led = scan.strip_leaders(start, end);
		reply |= led.1;
		start = led.0;
		// (6) A `[fwd: ...]` wrapper is removed and the whole run starts over.
		let wrapped = end - start >= 6
			&& scan.text[start..start + 5].eq_ignore_ascii_case(b"[fwd:")
			&& scan.text[end - 1] == b']';
		if !wrapped {
			// Every offset sits next to an ASCII byte, so the slice is UTF-8.
			return (text[start..end].to_ascii_uppercase(), reply);
		}
		reply = true;
		start += 5;
		end -= 1;
	}
}

/// The collapsed subject with, for every offset, where the next bracket is
/// and how many spaces start there.
struct Scan<'a> {
	text: &'a [u8],
	next_bracket: Vec<usize>,
	space_run: Vec<usize>,
}

impl<'a> Scan<'a> {
	fn new(text: &'a [u8]) -> Self {
		let mut next_bracket = vec![text.len(); text.len() + 1];
		let mut space_run = vec![0; text.len() + 1];
		for at in (0..text.len()).rev() {
			next_bracket[at] = if matches!(text[at], b'[' | b']') {
				at
			} else {
				next_bracket[at + 1]
			};
			space_run[at] = if text[at] == b' ' {
				space_run[at + 1] + 1
			} else {
				0
			};
		}
		Self {
			text,
			next_bracket,
			space_run,
		}
	}

	/// (2) The end left after removing trailing spaces and `(fwd)` trailers,
	/// and whether a trailer was among them.
	fn strip_trailers(&self, start: usize, mut end: usize) -> (usize, bool) {
		let mut forward = false;
		loop {
			if end > start && self.text[end - 1] == b' ' {
				end -= 1;
			} else if end - start >= 5 && self.text[end - 5..end].eq_ignore_ascii_case(b"(fwd)") {
				end -= 5;
				forward = true;
			} else {
				return (end, forward);
			}
		}
	}

	/// (3) to (5): the start left after removing leading spaces,
	/// `*subj-blob subj-refwd` leaders, and blobs with something after them,
	/// and whether a leader was among them.
	fn strip_leaders(&self, mut start: usize, end: usize) -> (usize, bool) {
		let mut leader = false;
		loop {
			start += self.spaces(start, end);
			// The blobs in front, then the leader they may introduce.
			let mut at = start;
			let mut last_blob = None;
			while let Some(after) = self.blob(at, end) {
				last_blob = Some(at);
				at = after;
			}
			if let Some(after) = self.refwd(at, end) {
				start = after;
				leader = true;
				continue;
			}
			// No leader follows the blobs, and none can appear by dropping
			// them, so (4) drops them one by one while something is left
			// after each: all of them, or all but the last when they run to
			// the end of the subject.
			let start = match last_blob {
				Some(last) if at == end => last,
				_ => at,
			};
			return (start, leader);
		}
	}

	/// The end of a `re`, `fw` or `fwd` leader at `at`: the word, optional
	/// spaces, an optional blob, then a colon.
	fn refwd(&self, at: usize, end: usize) -> Option<usize> {
		let word = |token: &[u8]| {
			end - at >= token.len() && self.text[at..at + token.len()].eq_ignore_ascii_case(token)
		};
		let mut after = if word(b"fwd") {
			at + 3
		} else if word(b"re") || word(b"fw") {
			at + 2
		} else {
			return None;
		};
		after += self.spaces(after, end);
		if let Some(blob_end) = self.blob(after, end) {
			after = blob_end;
		}
		(after < end && self.text[after] == b':').then_some(after + 1)
	}

	/// The end of a `[...]` blob (no brackets inside) and the spaces after
	/// it, starting at `at`.
	fn blob(&self, at: usize, end: usize) -> Option<usize> {
		if at >= end || self.text[at] != b'[' {
			return None;
		}
		let close = self.next_bracket[at + 1];
		if close >= end || self.text[close] != b']' {
			return None;
		}
		Some(close + 1 + self.spaces(close + 1, end))
	}

	fn spaces(&self, at: usize, end: usize) -> usize {
		self.space_run[at].min(end.saturating_sub(at))
	}
}

#[cfg(test)]
#[path = "base_subject_tests.rs"]
mod tests;
