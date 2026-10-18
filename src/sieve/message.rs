//! The message view the Sieve interpreter evaluates: parsed headers, total
//! size, body text, and the SMTP envelope.

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
	/// 10 000 headers and the first mebibyte of the body are kept: a message is up to the operator's size limit, and what
	/// the interpreter reads of it is a fixed window, so what it holds of it
	/// is too.
	pub fn parse(raw: &[u8]) -> Message {
		let blank = raw.windows(4).position(|w| w == b"\r\n\r\n");
		let header_end = blank.map_or(raw.len(), |p| p + 2);
		let body_start = blank.map_or(raw.len(), |p| p + 4);
		let whole_body = raw.get(body_start..).unwrap_or(&[]);
		// A little more than the window, so that cutting it at a character
		// boundary leaves the window whole.
		let kept = &whole_body[..whole_body.len().min(BODY_WINDOW + 4)];
		let body = String::from_utf8_lossy(kept).into_owned();
		let block = String::from_utf8_lossy(&raw[..header_end]);
		let mut headers = Vec::new();
		let mut headers_cut = false;
		let mut current: Option<String> = None;
		for line in block.split_inclusive('\n') {
			let content = line.trim_end_matches(['\r', '\n']);
			if content.starts_with(' ') || content.starts_with('\t') {
				if let Some(buffer) = &mut current {
					buffer.push(' ');
					buffer.push_str(content.trim_start());
				}
				continue;
			}
			if let Some(buffer) = current.take() {
				push_header(&mut headers, &buffer);
			}
			if !content.is_empty() {
				if headers.len() >= MAX_HEADERS {
					headers_cut = true;
					break;
				}
				current = Some(content.to_string());
			}
		}
		if let Some(buffer) = current.take() {
			push_header(&mut headers, &buffer);
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
			truncated: self.headers_cut,
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

fn push_header(headers: &mut Vec<(String, String)>, line: &str) {
	if let Some(colon) = line.find(':') {
		headers.push((
			line[..colon].trim_end().to_string(),
			line[colon + 1..].trim().to_string(),
		));
	}
}
