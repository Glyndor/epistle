//! The message view the Sieve interpreter evaluates: parsed headers, total
//! size, body text, and the SMTP envelope.

use crate::util::header_block;

use super::env::{
	BODY_WINDOW, HEADER_NAME_VALUES, HEADER_NAME_WINDOW, HEADER_NAMES_PER_LOOKUP, MAX_HEADERS,
};

/// A message as the interpreter sees it: parsed headers, total size, and the
/// SMTP envelope (for the `envelope` test).
pub struct Message {
	headers: Vec<(String, String)>,
	/// Where each header name (lower case) occurs in `headers`, in order,
	/// built once so that a lookup costs what it finds and not a pass over
	/// every header: a message may carry millions of them.
	index: std::collections::HashMap<String, Vec<u32>>,
	/// The message had more headers than [`MAX_HEADERS`]; the rest were not
	/// read.
	headers_cut: bool,
	/// Some header was longer than is kept of it.
	values_cut: bool,
	pub(super) size: usize,
	/// The first [`BODY_WINDOW`] octets of the body (a few more, cut again
	/// by [`Message::body_window`]): the rest is never read, so it is not
	/// copied.
	pub(super) body: String,
	/// The body is longer than what is kept of it.
	body_cut: bool,
	pub(super) envelope_from: Option<String>,
	pub(super) envelope_to: Vec<String>,
	/// Evaluation time (Unix seconds) for `currentdate`; tests inject it.
	pub(super) now: Option<u64>,
	/// Mailbox names the recipient account has, in their on-disk spelling
	/// (INBOX plus the IMAP modified UTF-7 names). `None` when the
	/// delivery path did not supply one, so the `mailboxexists` test
	/// fails safe. Sorted for deterministic membership checks.
	pub(super) mailboxes: Option<Vec<String>>,
}

impl Message {
	/// Parse headers (unfolded) and record the total size. Only the first
	/// 10 000 headers and the first mebibyte of the body are kept, and no
	/// header more than 64 KiB of itself: a message is up to the operator's
	/// size limit, and what the interpreter reads of it is a fixed window, so
	/// what it holds of it is too. Octets that are not UTF-8 become one `?`
	/// each, so text is never longer than the octets it came from.
	pub fn parse(raw: &[u8]) -> Message {
		let (block, whole_body) = header_block::split(raw);
		// A little more than the window, so that cutting it at a character
		// boundary leaves the window whole.
		let kept = &whole_body[..whole_body.len().min(BODY_WINDOW + 4)];
		let body = String::from_utf8_lossy(kept).into_owned();
		let mut headers = Vec::new();
		let mut headers_cut = false;
		let mut values_cut = false;
		let mut current: Option<Field> = None;
		for line in header_block::lines(block) {
			if !header_block::begins_field(line) {
				if let Some(field) = &mut current {
					values_cut |= field.feed(line);
				}
				continue;
			}
			if let Some(field) = current.take() {
				field.push_into(&mut headers);
			}
			if headers.len() >= MAX_HEADERS {
				headers_cut = true;
				break;
			}
			// A name is at most 998 octets (RFC 5322); a line with no colon
			// in that many is not a header.
			let head = &line[..line.len().min(MAX_NAME + 1)];
			match head.iter().position(|b| *b == b':') {
				Some(colon) => {
					let mut field = Field::named(&line[..colon]);
					values_cut |= field.feed(&line[colon + 1..]);
					current = Some(field);
				}
				None => values_cut |= line.len() > MAX_NAME,
			}
		}
		if let Some(field) = current.take() {
			field.push_into(&mut headers);
		}
		let mut index: std::collections::HashMap<String, Vec<u32>> =
			std::collections::HashMap::new();
		for (position, (name, _)) in headers.iter().enumerate() {
			index
				.entry(name.to_ascii_lowercase())
				.or_default()
				.push(u32::try_from(position).unwrap_or(u32::MAX));
		}
		Message {
			headers,
			index,
			headers_cut,
			values_cut,
			size: raw.len(),
			body,
			body_cut: whole_body.len() > kept.len(),
			envelope_from: None,
			envelope_to: Vec::new(),
			now: None,
			mailboxes: None,
		}
	}

	/// Attach the SMTP envelope (MAIL FROM and RCPT TO) for the `envelope` test.
	pub fn with_envelope(mut self, from: impl Into<String>, to: Vec<String>) -> Self {
		self.envelope_from = Some(from.into());
		self.envelope_to = to;
		self
	}

	/// Fix the evaluation time (Unix seconds) used by `currentdate` (tests).
	pub fn with_now(mut self, now: u64) -> Self {
		self.now = Some(now);
		self
	}

	/// Attach the recipient account's mailbox list, in their IMAP
	/// on-disk spelling (UTF-8 names go through modified UTF-7, the way
	/// `imap::mailbox::list` returns them). Used by the `mailboxexists`
	/// test (RFC 5490). `None` leaves the test failing safe, so a script
	/// is never true on a missing mailbox set.
	pub fn with_mailboxes(mut self, mailboxes: &mut [String]) -> Self {
		mailboxes.sort();
		self.mailboxes = Some(mailboxes.to_vec());
		self
	}

	/// Whether the message had more headers than are read.
	pub(super) fn headers_cut(&self) -> bool {
		self.headers_cut
	}

	/// Whether a header is called `name` (ignoring case).
	pub(super) fn has_header(&self, name: &str) -> bool {
		!self.positions(name).is_empty()
	}

	/// The headers called any of `names` (ignoring case) that a test can see,
	/// in order. What a lookup reads is a fixed window whatever the message
	/// holds, and every name has a quota of its own: at most
	/// [`HEADER_NAME_VALUES`] values and [`HEADER_NAME_WINDOW`] octets of
	/// them, and no more than [`HEADER_NAMES_PER_LOOKUP`] names. `truncated`
	/// says the window cut something, headers past [`MAX_HEADERS`] included.
	/// `count` is the number of headers read, which is all of them unless
	/// `truncated`.
	pub(super) fn visible_headers<S: AsRef<str>>(&self, names: &[S]) -> Visible<'_> {
		let mut seen = Visible {
			truncated: self.headers_cut || self.values_cut,
			headers_cut: self.headers_cut,
			..Visible::default()
		};
		for (n, name) in names.iter().enumerate() {
			let positions = self.positions(name.as_ref());
			seen.count += positions.len();
			if n >= HEADER_NAMES_PER_LOOKUP {
				seen.truncated |= !positions.is_empty();
				continue;
			}
			let mut room = HEADER_NAME_WINDOW;
			for (taken, position) in positions.iter().enumerate() {
				if taken >= HEADER_NAME_VALUES || room == 0 {
					seen.truncated = true;
					break;
				}
				let value = self.headers[*position as usize].1.as_str();
				let shown = window(value, room);
				seen.truncated |= shown.len() < value.len();
				room -= shown.len();
				seen.values.push(shown);
			}
		}
		seen
	}

	/// The part of the body the `body` test reads: the first [`BODY_WINDOW`]
	/// octets, and whether that is not all of it.
	pub(super) fn body_window(&self) -> (&str, bool) {
		let shown = window(&self.body, BODY_WINDOW);
		(shown, self.body_cut || shown.len() < self.body.len())
	}

	fn positions(&self, name: &str) -> &[u32] {
		let found = if name.bytes().any(|b| b.is_ascii_uppercase()) {
			self.index.get(name.to_ascii_lowercase().as_str())
		} else {
			self.index.get(name)
		};
		found.map_or(&[], Vec::as_slice)
	}
}

/// What a lookup of headers can see.
#[derive(Default)]
pub(super) struct Visible<'a> {
	pub(super) values: Vec<&'a str>,
	/// How many headers there are of those names, whatever the window.
	pub(super) count: usize,
	pub(super) truncated: bool,
	/// The message had more headers than are read, so `count` is of those
	/// read and not of all.
	pub(super) headers_cut: bool,
}

/// The first `limit` octets of `text`, cut at a character boundary.
fn window(text: &str, limit: usize) -> &str {
	let mut end = text.len().min(limit);
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	&text[..end]
}

/// The longest header name read, in octets (RFC 5322 section 2.1.1).
const MAX_NAME: usize = 998;

/// Text from octets, a `?` for each one that is not UTF-8: never longer than
/// the octets, which is what keeps a message of bad octets from costing
/// three times its size once converted.
fn decode(bytes: &[u8]) -> impl Iterator<Item = char> + '_ {
	bytes.utf8_chunks().flat_map(|chunk| {
		chunk
			.valid()
			.chars()
			.chain(std::iter::repeat_n('?', chunk.invalid().len()))
	})
}

/// A header being read: its name, and its value as the interpreter sees it,
/// built as the octets come: every run of white space (folding included) is
/// one space, the ends are trimmed, and no more than 64 KiB are kept. The
/// blanks are collapsed before the cut, so padding with them cannot push the
/// text that follows out of the window. White space is what `char::is_whitespace`
/// says: space, tab, VT, FF, CR, NEL, NBSP and the other Unicode blanks.
struct Field {
	name: String,
	value: String,
	blank: bool,
}

impl Field {
	fn named(name: &[u8]) -> Self {
		let name: String = decode(name).collect();
		Self {
			name: name.trim_end().to_string(),
			value: String::new(),
			blank: false,
		}
	}

	/// Add `text` (a piece of a line); `true` when the value is full and some
	/// of it was left out.
	fn feed(&mut self, text: &[u8]) -> bool {
		for c in decode(text) {
			if c.is_whitespace() {
				self.blank = !self.value.is_empty();
				continue;
			}
			let room = c.len_utf8() + usize::from(self.blank);
			if self.value.len() + room > HEADER_NAME_WINDOW {
				return true;
			}
			if std::mem::take(&mut self.blank) {
				self.value.push(' ');
			}
			self.value.push(c);
		}
		false
	}

	fn push_into(mut self, headers: &mut Vec<(String, String)>) {
		// Built by pushing, so it holds up to twice what it needs.
		self.value.shrink_to_fit();
		headers.push((self.name, self.value));
	}
}
