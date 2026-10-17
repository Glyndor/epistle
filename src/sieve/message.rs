//! The message view the Sieve interpreter evaluates: parsed headers, total
//! size, body text, and the SMTP envelope.

/// A message as the interpreter sees it: parsed headers, total size, and the
/// SMTP envelope (for the `envelope` test).
pub struct Message {
	headers: Vec<(String, String)>,
	/// Where each header name (lower case) occurs in `headers`, in order,
	/// built once so that a lookup costs what it finds and not a pass over
	/// every header: a message may carry millions of them.
	index: std::collections::HashMap<String, Vec<u32>>,
	pub(super) size: usize,
	pub(super) body: String,
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
	/// Parse headers (unfolded) and record the total size.
	pub fn parse(raw: &[u8]) -> Message {
		let header_end = raw
			.windows(4)
			.position(|w| w == b"\r\n\r\n")
			.map(|p| p + 2)
			.unwrap_or(raw.len());
		let body_start = raw
			.windows(4)
			.position(|w| w == b"\r\n\r\n")
			.map(|p| p + 4)
			.unwrap_or(raw.len());
		let body = String::from_utf8_lossy(raw.get(body_start..).unwrap_or(&[])).into_owned();
		let block = String::from_utf8_lossy(&raw[..header_end]);
		let mut headers = Vec::new();
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
			size: raw.len(),
			body,
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

	/// How many headers are called `name` (ignoring case).
	pub(super) fn header_count(&self, name: &str) -> usize {
		self.positions(name).len()
	}

	/// The values of the headers called `name` (ignoring case), in order.
	pub(super) fn header_values<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> {
		self.positions(name)
			.iter()
			.map(|position| self.headers[*position as usize].1.as_str())
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

fn push_header(headers: &mut Vec<(String, String)>, line: &str) {
	if let Some(colon) = line.find(':') {
		headers.push((
			line[..colon].trim_end().to_string(),
			line[colon + 1..].trim().to_string(),
		));
	}
}
