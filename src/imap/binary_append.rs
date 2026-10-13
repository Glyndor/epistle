//! Storage form of a message APPENDed as a literal8 (RFC 3516 §4.4).
//!
//! A part with `Content-Transfer-Encoding: binary` may hold NUL and bare
//! line ends, which no plain IMAP literal can carry, so BODY[] could not
//! return it. Such parts are stored base64 encoded, with the header saying
//! so; BINARY[] decodes them back to the octets the client sent.

use base64::Engine;
use mail_parser::{HeaderName, Message, PartType};

/// Base64 output line length (RFC 2045 §6.8 allows at most 76).
const LINE: usize = 76;

/// `raw` with every binary leaf part re-encoded as base64, or `None` when
/// there is none and the message is stored as sent.
pub(super) fn encode_binary_parts(raw: &[u8]) -> Option<Vec<u8>> {
	let message = super::fetch::parse(raw);
	let mut edits = Vec::new();
	collect(&message, raw, 0, &mut edits);
	if edits.is_empty() {
		return None;
	}
	edits.sort_by_key(|edit| edit.0);
	let mut out = Vec::with_capacity(raw.len() * 4 / 3 + 64);
	let mut at = 0;
	for (start, end, replacement) in edits {
		if start < at || end > raw.len() {
			return None;
		}
		out.extend_from_slice(&raw[at..start]);
		out.extend_from_slice(&replacement);
		at = end;
	}
	out.extend_from_slice(&raw[at..]);
	Some(out)
}

type Edit = (usize, usize, Vec<u8>);

/// Queue the header and body replacements for each binary leaf of
/// `message`, descending into encapsulated messages that share `raw`'s
/// offsets, at most as deep as FETCH looks. A message the parser decoded
/// into a buffer of its own (an encoded message/rfc822 part) is left alone:
/// its offsets are not `raw`'s.
fn collect(message: &Message<'_>, raw: &[u8], depth: usize, edits: &mut Vec<Edit>) {
	if depth > super::fetch::MAX_DEPTH || message.raw_message.as_ptr() != raw.as_ptr() {
		return;
	}
	for part in &message.parts {
		match &part.body {
			PartType::Multipart(_) => {}
			PartType::Message(nested) => collect(nested, raw, depth + 1, edits),
			_ => {
				let Some(header) = part
					.headers
					.iter()
					.find(|h| h.name == HeaderName::ContentTransferEncoding)
				else {
					continue;
				};
				let (start, end) = (header.offset_start as usize, header.offset_end as usize);
				let value = raw.get(start..end).unwrap_or_default().trim_ascii();
				if !value.eq_ignore_ascii_case(b"binary") {
					continue;
				}
				let body = (part.offset_body as usize, part.offset_end as usize);
				let Some(content) = raw.get(body.0..body.1) else {
					continue;
				};
				edits.push((start, end, b" base64\r\n".to_vec()));
				edits.push((body.0, body.1, base64_lines(content)));
			}
		}
	}
}

fn base64_lines(bytes: &[u8]) -> Vec<u8> {
	let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
	let mut out = Vec::with_capacity(encoded.len() + encoded.len() / LINE * 2);
	for (index, chunk) in encoded.as_bytes().chunks(LINE).enumerate() {
		if index > 0 {
			out.extend_from_slice(b"\r\n");
		}
		out.extend_from_slice(chunk);
	}
	out
}
