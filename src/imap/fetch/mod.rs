//! MIME-backed FETCH response serialization.

pub(super) mod bodystructure;
pub(super) mod envelope;
pub(super) mod section;

use mail_parser::{HeaderName, Message, MessageParser, MessagePart};

// Count MIME edges from the root, including encapsulated message roots.
pub(super) const MAX_DEPTH: usize = 64;

pub(super) struct ParsedMessage<'a> {
	message: Message<'a>,
	raw: &'a [u8],
	fallback: bool,
}

impl<'a> std::ops::Deref for ParsedMessage<'a> {
	type Target = Message<'a>;

	fn deref(&self) -> &Self::Target {
		&self.message
	}
}

pub(super) fn parse(raw: &[u8]) -> ParsedMessage<'_> {
	// The consumers stop at `MAX_DEPTH` and keep anything below it opaque, so
	// the reader need not nest further. One level of theirs can cross a
	// message root and a multipart edge, which are two levels of the
	// reader's, hence twice the budget plus the root. Without the bound a message nested
	// a hundred thousand `message/rfc822` deep takes about a minute to parse
	// (the cost grows with the square of the depth). The part count stays
	// unbounded as in 0.11: cutting it would hide attachments from the scan,
	// and a flat message with 200 000 parts parses in under a second.
	let parsed = MessageParser::default()
		.max_depth(2 * MAX_DEPTH + 2)
		.max_parts(usize::MAX)
		.parse(raw);
	let fallback = parsed.is_none();
	ParsedMessage {
		message: parsed.unwrap_or_default(),
		raw,
		fallback,
	}
}

/// Render BODYSTRUCTURE and ENVELOPE for the whole of `raw`, the way a
/// FETCH does, and return the response size. Entry point for the MIME
/// fuzz target.
pub(crate) fn render_for_fuzzing(raw: &[u8]) -> usize {
	let message = parse(raw);
	bodystructure::render(&message, 0, true).len() + envelope::render(&message, 0).len()
}

pub(super) fn raw_header<'a>(part: &MessagePart<'a>, name: HeaderName<'_>) -> Option<&'a [u8]> {
	// The old reader selected the first matching field.
	let header = part.headers().iter().find(|h| h.name() == name)?;
	Some(header.raw_value().trim_ascii())
}

pub(super) fn string(value: Option<&[u8]>) -> Vec<u8> {
	let Some(value) = value else {
		return b"NIL".to_vec();
	};
	if value.len() > 1024
		|| value
			.iter()
			.any(|b| !b.is_ascii() || b.is_ascii_control() || *b == b'"')
	{
		let mut out = format!("{{{}}}\r\n", value.len()).into_bytes();
		out.extend_from_slice(value);
		out
	} else {
		let mut out = vec![b'"'];
		for b in value {
			if *b == b'\\' {
				out.push(b'\\');
			}
			out.push(*b);
		}
		out.push(b'"');
		out
	}
}

pub(super) fn list(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
	let mut out = vec![b'('];
	for (i, value) in values.into_iter().enumerate() {
		if i > 0 {
			out.push(b' ');
		}
		out.extend(value);
	}
	out.push(b')');
	out
}

pub(super) fn source<'a>(message: &'a ParsedMessage<'_>, part: &MessagePart<'a>) -> &'a [u8] {
	if message.fallback {
		message.raw
	} else {
		part.message().source_bytes()
	}
}

pub(super) fn body_end(message: &ParsedMessage<'_>, part: &MessagePart<'_>) -> usize {
	if message.fallback {
		message.raw.len()
	} else {
		part.offset_end() as usize
	}
}

pub(super) fn raw_body<'a>(message: &'a ParsedMessage<'_>, part: &MessagePart<'a>) -> &'a [u8] {
	source(message, part)
		.get(part.offset_body() as usize..body_end(message, part))
		.unwrap_or_default()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::imap::command::{FetchSection, SectionKind};
	use base64::Engine;

	/// A message that nests `message/rfc822` a hundred thousand levels deep
	/// is parsed, rendered and dropped on a stack far smaller than a
	/// recursive walk of the tree would need: an overflow aborts the whole
	/// process, so passing is the evidence that nothing here recurses.
	#[test]
	fn a_message_nested_a_hundred_thousand_deep_does_not_exhaust_a_small_stack() {
		let mut raw = "Content-Type: message/rfc822\r\n\r\n".repeat(100_000);
		raw.push_str("Subject: leaf\r\n\r\nbody");
		std::thread::Builder::new()
			.stack_size(256 * 1024)
			.spawn(move || {
				let parsed = parse(raw.as_bytes());
				assert!(parsed.parts().count() <= 2 * MAX_DEPTH + 2);
				assert!(!bodystructure::render(&parsed, 0, true).is_empty());
				drop(parsed);
			})
			.expect("spawn the small-stack thread")
			.join()
			.expect("the thread ends without a panic");
	}

	#[test]
	fn an_unreadable_message_keeps_its_fallback_body() {
		let raw = b"\xffunstructured";
		let parsed = parse(raw);
		assert!(parsed.fallback);
		assert_eq!(raw_body(&parsed, &parsed.root().root_part()), raw);
		let request = FetchSection {
			path: Vec::new(),
			kind: SectionKind::Text,
			partial: None,
			peek: true,
			binary: false,
			size: false,
		};
		let mut expected = format!("BODY[TEXT] {{{}}}\r\n", raw.len()).into_bytes();
		expected.extend_from_slice(raw);
		assert_eq!(section::render(&parsed, &request), Ok(expected));
	}

	#[test]
	fn encoded_nested_sections_keep_their_sources_and_legacy_text_bounds() {
		let inner = b"Subject: nested\r\n\r\nInside";
		let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
		let raw = format!(
			"Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}"
		);
		let parsed = parse(raw.as_bytes());
		let mut request = FetchSection {
			path: vec![1, 1],
			kind: SectionKind::Entire,
			partial: None,
			peek: true,
			binary: true,
			size: false,
		};
		assert_eq!(
			section::render(&parsed, &request),
			Ok(b"BINARY[1.1] {6}\r\nInside".to_vec())
		);
		request.path = vec![1];
		request.kind = SectionKind::Header;
		request.binary = false;
		assert_eq!(
			section::render(&parsed, &request),
			Ok(b"BODY[1.HEADER] {19}\r\nSubject: nested\r\n\r\n".to_vec())
		);
		// The old TEXT path kept the encoded container's end offset. That
		// range is outside the decoded source and therefore returned empty.
		request.kind = SectionKind::Text;
		assert_eq!(
			section::render(&parsed, &request),
			Ok(b"BODY[1.TEXT] {0}\r\n".to_vec())
		);
	}
}
