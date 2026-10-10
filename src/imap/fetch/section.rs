//! Raw MIME sections and transfer-decoded BINARY sections.

use super::{raw_body, raw_header};
use crate::imap::command::{FetchSection, SectionKind};
use mail_parser::{HeaderName, Message, MessagePart, PartType};

pub(in crate::imap) fn render(
	message: &Message<'_>,
	section: &FetchSection,
) -> Result<Vec<u8>, ()> {
	render_label(message, section, &section.label())
}

pub(in crate::imap) fn render_label(
	message: &Message<'_>,
	section: &FetchSection,
	label: &str,
) -> Result<Vec<u8>, ()> {
	let Some((mut owner, mut part)) = select(message, &section.path) else {
		return Ok(format!("{label} NIL").into_bytes());
	};
	if !section.path.is_empty()
		&& matches!(
			section.kind,
			SectionKind::Header | SectionKind::Text | SectionKind::Fields { .. }
		) {
		let PartType::Message(nested) = &part.body else {
			return Ok(format!("{label} NIL").into_bytes());
		};
		owner = nested;
		let Some(root) = owner.parts.first() else {
			return Ok(format!("{label} NIL").into_bytes());
		};
		part = root;
	}
	let mut data = match &section.kind {
		SectionKind::Entire if section.path.is_empty() && !section.binary => {
			owner.raw_message().to_vec()
		}
		SectionKind::Entire | SectionKind::Text => raw_body(owner, part).to_vec(),
		SectionKind::Header | SectionKind::Mime => owner
			.raw_message
			.get(part.offset_header as usize..part.offset_body as usize)
			.unwrap_or_default()
			.to_vec(),
		SectionKind::Fields { names, exclude } => {
			let mut data = Vec::new();
			for header in &part.headers {
				let included = names
					.iter()
					.any(|n| n.eq_ignore_ascii_case(header.name.as_str()));
				if included != *exclude {
					data.extend_from_slice(
						owner
							.raw_message
							.get(header.offset_field as usize..header.offset_end as usize)
							.unwrap_or_default(),
					);
				}
			}
			data.extend_from_slice(b"\r\n");
			data
		}
	};
	if section.binary {
		data = decoded(owner, part)?;
	}
	if section.size {
		return Ok(format!("{label} {}", data.len()).into_bytes());
	}
	let data = if let Some((start, count)) = section.partial {
		data.get(start..start.saturating_add(count).min(data.len()))
			.unwrap_or_default()
	} else {
		&data
	};
	let literal8 = if section.binary && data.contains(&0) {
		"~"
	} else {
		""
	};
	let mut out = format!("{label} {literal8}{{{}}}\r\n", data.len()).into_bytes();
	out.extend_from_slice(data);
	Ok(out)
}

pub(super) fn decoded(message: &Message<'_>, part: &MessagePart<'_>) -> Result<Vec<u8>, ()> {
	let body = raw_body(message, part);
	let encoding =
		raw_header(message, part, HeaderName::ContentTransferEncoding).unwrap_or(b"7bit");
	if encoding.eq_ignore_ascii_case(b"base64") {
		mail_parser::decoders::base64::base64_decode(body).ok_or(())
	} else if encoding.eq_ignore_ascii_case(b"quoted-printable") {
		mail_parser::decoders::quoted_printable::quoted_printable_decode(body).ok_or(())
	} else if [b"7bit".as_slice(), b"8bit", b"binary"]
		.iter()
		.any(|known| encoding.eq_ignore_ascii_case(known))
	{
		Ok(body.to_vec())
	} else {
		Err(())
	}
}

fn select<'a>(
	message: &'a Message<'a>,
	path: &[u32],
) -> Option<(&'a Message<'a>, &'a MessagePart<'a>)> {
	let mut owner = message;
	let mut part = owner.parts.first()?;
	for (depth, number) in path.iter().enumerate() {
		let mut entered_message = false;
		if depth > 0
			&& let PartType::Message(nested) = &part.body
		{
			owner = nested;
			part = owner.parts.first()?;
			entered_message = true;
		}
		if let PartType::Multipart(children) = &part.body {
			let id = children.get(usize::try_from(*number).ok()?.checked_sub(1)?)?;
			part = owner.parts.get(*id as usize)?;
		} else if *number != 1 || (depth != 0 && !entered_message) {
			return None;
		}
	}
	Some((owner, part))
}
