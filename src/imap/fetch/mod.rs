//! MIME-backed FETCH response serialization.

pub(super) mod bodystructure;
pub(super) mod envelope;
pub(super) mod section;

use mail_parser::{HeaderName, Message, MessageParser, MessagePart};

pub(super) fn parse(raw: &[u8]) -> Message<'_> {
	MessageParser::default()
		.parse(raw)
		.unwrap_or_else(|| Message {
			raw_message: raw.into(),
			parts: vec![MessagePart {
				offset_end: raw.len() as u32,
				body: mail_parser::PartType::Text("".into()),
				..Default::default()
			}],
			..Default::default()
		})
}

pub(super) fn raw_header<'a>(
	message: &'a Message<'_>,
	part: &MessagePart<'_>,
	name: HeaderName<'_>,
) -> Option<&'a [u8]> {
	let header = part.headers.iter().find(|h| h.name == name)?;
	let value = message
		.raw_message
		.get(header.offset_start as usize..header.offset_end as usize)?;
	Some(value.trim_ascii())
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

pub(super) fn raw_body<'a>(message: &'a Message<'_>, part: &MessagePart<'_>) -> &'a [u8] {
	message
		.raw_message
		.get(part.offset_body as usize..part.offset_end as usize)
		.unwrap_or_default()
}
