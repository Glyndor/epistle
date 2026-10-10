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
	if section.path.len() > super::MAX_DEPTH {
		return Ok(empty(section, label));
	}
	let Selected {
		mut owner,
		mut part,
		depth,
	} = match select(message, &section.path) {
		Ok(selected) => selected,
		Err(SelectError::TooDeep) => return Ok(empty(section, label)),
		Err(SelectError::Missing) => return Ok(format!("{label} NIL").into_bytes()),
	};
	if !section.path.is_empty()
		&& matches!(
			section.kind,
			SectionKind::Header | SectionKind::Text | SectionKind::Fields { .. }
		) {
		if depth >= super::MAX_DEPTH {
			return Ok(empty(section, label));
		}
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

fn empty(section: &FetchSection, label: &str) -> Vec<u8> {
	if section.size {
		format!("{label} 0").into_bytes()
	} else {
		format!("{label} {{0}}\r\n").into_bytes()
	}
}

struct Selected<'a> {
	owner: &'a Message<'a>,
	part: &'a MessagePart<'a>,
	depth: usize,
}

enum SelectError {
	Missing,
	TooDeep,
}

fn select<'a>(message: &'a Message<'a>, path: &[u32]) -> Result<Selected<'a>, SelectError> {
	let mut owner = message;
	let mut part = owner.parts.first().ok_or(SelectError::Missing)?;
	let mut mime_depth = 0;
	for (depth, number) in path.iter().enumerate() {
		let mut entered_message = false;
		if depth > 0
			&& let PartType::Message(nested) = &part.body
		{
			mime_depth += 1;
			if mime_depth > super::MAX_DEPTH {
				return Err(SelectError::TooDeep);
			}
			owner = nested;
			part = owner.parts.first().ok_or(SelectError::Missing)?;
			entered_message = true;
		}
		if let PartType::Multipart(children) = &part.body {
			mime_depth += 1;
			if mime_depth > super::MAX_DEPTH {
				return Err(SelectError::TooDeep);
			}
			let index = usize::try_from(*number)
				.ok()
				.and_then(|number| number.checked_sub(1))
				.ok_or(SelectError::Missing)?;
			let id = children.get(index).ok_or(SelectError::Missing)?;
			part = owner.parts.get(*id as usize).ok_or(SelectError::Missing)?;
		} else if *number != 1 || (depth != 0 && !entered_message) {
			return Err(SelectError::Missing);
		}
	}
	Ok(Selected {
		owner,
		part,
		depth: mime_depth,
	})
}
