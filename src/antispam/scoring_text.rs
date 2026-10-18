//! The text a message is scored and trained on.
//!
//! The filter reads what a person reads, not the bytes that carry it: the
//! header block and the text parts, decoded, as a stream of the tokens the
//! classifier would take from them. Three things follow from that.
//!
//! - A base64 attachment, a photo or a PDF is not text. Tokenising it makes
//!   thousands of words nobody wrote, so a perfectly ordinary message with an
//!   attachment looked like one with a pile of filler, and a spammer could
//!   put the filler there. Parts that are not `text/*` are skipped, and cost
//!   nothing of the window.
//! - Whitespace, punctuation and one-letter words are not tokens, so filler
//!   made of them costs nothing of the window either; a message of 25 MiB
//!   with a spam paragraph in the middle of spaces is read in full.
//! - What is left is cut to a window of [`MAX_TRAINING_BYTES`] of tokens: the
//!   first half and the last half. A message that does not fit is `clipped`,
//!   and the scorer treats it as one it has not read in full.
//!
//! The pass is linear, keeps at most about 400 KiB of tokens in memory and
//! never decodes more than [`MAX_DECODED`] of the message's parts. A message
//! whose structure the walk gives up on (too deep, too many parts) or whose
//! text does not fit in the decoding budget is read as the raw bytes
//! instead, which is what the filter always did, so nothing is skipped
//! because the structure was odd.

use super::attachments::walk::{self, Limits, MAX_HEADER_BYTES};
use super::training_queue::MAX_TRAINING_BYTES;

/// Most decoded bytes the walk produces for one message. Decoded text parts
/// are held in memory while the message is read.
pub const MAX_DECODED: usize = 2 * 1024 * 1024;

/// Deepest nesting and most parts followed; the figures the attachment
/// inspection uses.
const MAX_DEPTH: usize = 10;
const MAX_PARTS: usize = 1000;

/// Extra room the tail may grow to before its oldest tokens are dropped,
/// so dropping them is not done token by token.
const TAIL_SLACK: usize = 64 * 1024;

/// A message reduced to what is scored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScoringText {
	/// The tokens, separated by spaces; when the message did not fit, the
	/// first half, a newline and the last half.
	pub text: String,
	/// The message had more text than fits in the window, and the middle was
	/// left out.
	pub clipped: bool,
}

/// Reduce the raw message `raw` to the text it is scored and trained on.
pub fn scoring_text(raw: &[u8]) -> ScoringText {
	let mut window = Window::default();
	match extract(raw, &mut window) {
		Some(()) => window.finish(),
		None => {
			// The structure or the size defeated the walk: read the bytes.
			let mut window = Window::default();
			window.push_bytes(raw);
			window.finish()
		}
	}
}

/// Feed the header block and the text parts of `raw` to `window`. `None`
/// when the message could not be read part by part.
fn extract(raw: &[u8], window: &mut Window) -> Option<()> {
	window.push_bytes(header_block(raw));
	let limits = Limits {
		max_depth: MAX_DEPTH,
		max_parts: MAX_PARTS,
		max_decoded: MAX_DECODED,
		deadline: None,
	};
	let mut complete = true;
	let mut parts: Vec<Vec<u8>> = Vec::new();
	let walked = walk::walk(raw, &limits, |leaf| {
		if leaf.declared_type.starts_with("text/") {
			// A text part cut short by the budget is not all of the text.
			complete &= !leaf.truncated;
			parts.push(leaf.content);
		}
	});
	if walked.stopped.is_some() || !complete {
		return None;
	}
	for part in &parts {
		window.push_bytes(part);
	}
	Some(())
}

/// The header block of the message: up to the first empty line, at most
/// [`MAX_HEADER_BYTES`].
fn header_block(raw: &[u8]) -> &[u8] {
	let limit = raw.len().min(MAX_HEADER_BYTES);
	let mut start = 0;
	while start < limit {
		let end = raw[start..limit]
			.iter()
			.position(|&byte| byte == b'\n')
			.map_or(limit, |offset| start + offset);
		let line = &raw[start..end];
		if line.is_empty() || line == b"\r" {
			return &raw[..start];
		}
		start = end + 1;
	}
	&raw[..limit]
}

/// The first and the last half of a stream of tokens, built as it goes.
#[derive(Default)]
struct Window {
	head: String,
	/// Whether the head is full: later tokens go to the tail.
	head_full: bool,
	tail: String,
	/// Tokens were dropped from the front of the tail.
	dropped: bool,
}

impl Window {
	const HEAD: usize = MAX_TRAINING_BYTES / 2;

	/// Bytes of valid text are split into tokens; a byte that is not valid
	/// UTF-8 is a separator, as the lossy decoding makes it.
	fn push_bytes(&mut self, bytes: &[u8]) {
		for chunk in bytes.utf8_chunks() {
			self.push_str(chunk.valid());
		}
	}

	fn push_str(&mut self, text: &str) {
		for raw in text.split(|c: char| !c.is_alphanumeric()) {
			if (2..=30).contains(&raw.len()) {
				self.push_token(raw);
			}
		}
	}

	fn push_token(&mut self, token: &str) {
		if !self.head_full {
			if self.head.len() + token.len() < Self::HEAD {
				self.head.push_str(token);
				self.head.push(' ');
				return;
			}
			self.head_full = true;
		}
		self.tail.push_str(token);
		self.tail.push(' ');
		if self.tail.len() > MAX_TRAINING_BYTES - self.head.len() + TAIL_SLACK {
			self.drop_front();
		}
	}

	/// Drop the oldest tokens of the tail until what is left fits beside the head.
	fn drop_front(&mut self) {
		let keep = MAX_TRAINING_BYTES - self.head.len() - 1;
		if self.tail.len() <= keep {
			return;
		}
		let mut cut = self.tail.len() - keep;
		// Whole tokens only: tokens are ASCII-delimited by a space.
		if let Some(space) = self.tail[cut..].find(' ') {
			cut += space + 1;
		} else {
			cut = self.tail.len();
		}
		self.tail.drain(..cut);
		self.dropped = true;
	}

	fn finish(mut self) -> ScoringText {
		let fits = !self.dropped && self.head.len() + self.tail.len() <= MAX_TRAINING_BYTES;
		if fits {
			self.head.push_str(&self.tail);
			return ScoringText {
				text: self.head,
				clipped: false,
			};
		}
		self.drop_front();
		self.head.push('\n');
		self.head.push_str(&self.tail);
		ScoringText {
			text: self.head,
			clipped: true,
		}
	}
}

#[cfg(test)]
#[path = "scoring_text_tests.rs"]
mod tests;
