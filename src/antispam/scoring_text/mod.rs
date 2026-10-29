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
//!   nothing of the window nor of the decoding budget, so a large file
//!   cannot use up what the text after it needs.
//! - Whitespace, punctuation and one-letter words are not tokens, so filler
//!   made of them costs nothing of the window either; a message of 25 MiB
//!   with a spam paragraph in the middle of spaces is read in full.
//! - What is left is cut to a window of [`MAX_TRAINING_BYTES`] of tokens: the
//!   first half and the last half. A message that does not fit is `clipped`,
//!   and the scorer treats it as one it has not read in full.
//!
//! A message the walk calls ambiguous, one that two readers could split into
//! parts differently, is read as raw bytes as well, so that whatever either
//! reader shows is read; a part that declares two transfer encodings is read
//! under each, and text in a charset that is not UTF-8 is read as the person
//! sees it.
//!
//! The pass is linear, keeps at most about 400 KiB of tokens in memory and
//! never decodes more than [`MAX_DECODED`] of the message's parts. A message
//! whose structure the walk gives up on (too deep, too many parts) or whose
//! text does not fit in the decoding budget is read as the raw bytes
//! instead, which is what the filter always did, so nothing is skipped
//! because the structure was odd. Text that travels encoded is not decoded
//! that way, so such a message is `clipped`: one that was not read in full.

use super::attachments::walk::{self, Limits, MAX_HEADER_BYTES};
use super::training_queue::MAX_TRAINING_BYTES;

mod read;

/// Most decoded bytes the walk produces for one message. Decoded text parts
/// are held in memory while the message is read.
pub const MAX_DECODED: usize = 2 * 1024 * 1024;

/// Deepest nesting followed. A message nested deeper is read as bytes and is
/// `clipped`, which scores it at the floor of 0.5, under `bayes_junk_at`, so
/// the cap is also the depth at which text in base64 stops being read. The
/// walk keeps its open boundaries on a stack it owns and compares a line
/// with each of them, so the cost is linear in the depth: measured in release
/// on 25 MiB of near-delimiter lines with 60 bytes of prefix in common, about
/// 0.15 s at depth 10, 0.5 s at 32 and 1.2 s at 64.
const MAX_DEPTH: usize = 32;

/// Most parts followed. A part costs a fixed amount whatever the size of the
/// message: 20000 parts took 76 ms in debug.
const MAX_PARTS: usize = 10_000;

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
	/// The reduction failed, so nothing of the message was read. Nothing is
	/// learned from such a message: it has no words to count.
	pub unread: bool,
}

// Test-only: the next reduction on this thread panics, to prove what the
// callers do with a message that could not be read.
#[cfg(test)]
thread_local! {
	static FAIL_NEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make the next [`scoring_text`] on this thread fail.
#[cfg(test)]
pub(crate) fn fail_next_reduction() {
	FAIL_NEXT.with(|fail| fail.set(true));
}

/// Reduce the raw message `raw` to the text it is scored and trained on.
pub fn scoring_text(raw: &[u8]) -> ScoringText {
	// Whatever the walk or the window may do with a message of someone else's
	// making, it must not take the worker or the session down with it: a
	// message that cannot be reduced is one that was not read, never clean.
	std::panic::catch_unwind(|| reduce(raw)).unwrap_or_else(|_| {
		tracing::error!("reducing a message to its text failed");
		ScoringText {
			text: String::new(),
			clipped: true,
			unread: true,
		}
	})
}

fn reduce(raw: &[u8]) -> ScoringText {
	#[cfg(test)]
	if FAIL_NEXT.with(|fail| fail.replace(false)) {
		panic!("injected failure of the reduction");
	}
	let mut window = Window::default();
	match extract(raw, &mut window) {
		Some(()) => window.finish(),
		None => {
			// The structure or the size defeated the walk: read the bytes. Text
			// the message carries in an encoding is not decoded that way, so
			// it is not a message that was read in full.
			let mut window = Window::default();
			window.push_bytes(raw);
			let mut reduced = window.finish();
			reduced.clipped = true;
			reduced
		}
	}
}

/// Feed the header block and the text parts of `raw` to `window`. `None`
/// when the message could not be read part by part.
fn extract(raw: &[u8], window: &mut Window) -> Option<()> {
	read::push_header(window, header_block(raw));
	let limits = Limits {
		max_depth: MAX_DEPTH,
		max_parts: MAX_PARTS,
		max_decoded: MAX_DECODED,
		deadline: None,
	};
	let mut complete = true;
	let mut ambiguous = false;
	let mut parts: Vec<(Vec<u8>, Vec<String>)> = Vec::new();
	let walked = walk::walk_text(raw, &limits, |leaf| {
		ambiguous |= leaf.ambiguous;
		// A part that declares two types is text to one reader and a file to
		// another: it is read if any of them is text.
		let text = leaf.declared_type.starts_with("text/")
			|| leaf
				.declared_types
				.iter()
				.any(|declared| declared.starts_with("text/"));
		if text {
			// A text part cut short by the budget is not all of the text.
			complete &= !leaf.truncated;
			parts.push((leaf.content, leaf.charsets.clone()));
			// A client may have taken another of the encodings it declares.
			parts.extend(
				leaf.alternates
					.into_iter()
					.map(|content| (content, leaf.charsets.clone())),
			);
		} else if leaf.truncated
			&& leaf
				.declared_types
				.iter()
				.any(|kind| kind.starts_with("message/") || kind.starts_with("multipart/"))
		{
			// A message inside the message that the budget cut short holds text
			// that was not read.
			complete = false;
		}
	});
	if walked.stopped.is_some() || !complete {
		return None;
	}
	for (part, charsets) in &parts {
		read::push_part(window, part, charsets);
	}
	// Two readers could see this message differently: read the bytes as well,
	// so that whatever either of them shows is read.
	if ambiguous || walked.ambiguous {
		window.push_bytes(raw);
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
		if !text.is_ascii() {
			// `push_chars` drops what takes no room on the screen, so that it
			// does not split a word.
			read::push_chars(self, text.chars(), false);
			return;
		}
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
		// A byte offset can fall inside a character; whole tokens only, and a
		// token ends at an ASCII space, which is always a boundary, so the
		// cut after it is too.
		let cut = self.tail.len() - keep;
		let cut = match self.tail.as_bytes()[cut..]
			.iter()
			.position(|&byte| byte == b' ')
		{
			Some(space) => cut + space + 1,
			None => self.tail.len(),
		};
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
				unread: false,
			};
		}
		self.drop_front();
		self.head.push('\n');
		self.head.push_str(&self.tail);
		ScoringText {
			text: self.head,
			clipped: true,
			unread: false,
		}
	}
}

#[cfg(test)]
mod tests;
