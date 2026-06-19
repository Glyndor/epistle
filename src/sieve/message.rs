//! The message view the Sieve interpreter evaluates: parsed headers, total
//! size, body text, and the SMTP envelope.

/// A message as the interpreter sees it: parsed headers, total size, and the
/// SMTP envelope (for the `envelope` test).
pub struct Message {
	headers: Vec<(String, String)>,
	pub(super) size: usize,
	pub(super) body: String,
	pub(super) envelope_from: Option<String>,
	pub(super) envelope_to: Vec<String>,
	/// Evaluation time (Unix seconds) for `currentdate`; tests inject it.
	pub(super) now: Option<u64>,
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
		Message {
			headers,
			size: raw.len(),
			body,
			envelope_from: None,
			envelope_to: Vec::new(),
			now: None,
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

	pub(super) fn header_values(&self, name: &str) -> Vec<&str> {
		self.headers
			.iter()
			.filter(|(header, _)| header.eq_ignore_ascii_case(name))
			.map(|(_, value)| value.as_str())
			.collect()
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
