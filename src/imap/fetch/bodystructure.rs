//! RFC 9051 MIME tree and extension data.

use super::{envelope, list, raw_body, raw_header, string};
use mail_parser::{ContentType, HeaderName, HeaderValue, Message, MessagePart, PartType};

pub(in crate::imap) fn render(message: &Message<'_>, id: usize, extensions: bool) -> Vec<u8> {
	let Some(part) = message.parts.get(id) else {
		return b"NIL".to_vec();
	};
	let ct = content_type(part, HeaderName::ContentType);
	let (kind, subtype) = ct
		.map(|ct| {
			(
				ct.c_type.as_ref(),
				ct.c_subtype.as_deref().unwrap_or("plain"),
			)
		})
		.unwrap_or(match &part.body {
			PartType::Message(_) => ("message", "rfc822"),
			_ => ("text", "plain"),
		});
	if let PartType::Multipart(children) = &part.body {
		let mut out = vec![b'('];
		for id in children {
			out.extend(render(message, *id as usize, extensions));
		}
		out.push(b' ');
		out.extend(string(Some(subtype.to_ascii_uppercase().as_bytes())));
		if extensions {
			out.push(b' ');
			out.extend(parameters(ct));
			for field in extension_fields(message, part) {
				out.push(b' ');
				out.extend(field);
			}
		}
		out.push(b')');
		return out;
	}
	let body = raw_body(message, part);
	let params = if ct.is_none() && kind == "text" {
		b"(\"CHARSET\" \"US-ASCII\")".to_vec()
	} else {
		parameters(ct)
	};
	let encoding = raw_header(message, part, HeaderName::ContentTransferEncoding)
		.map(|v| v.to_ascii_uppercase())
		.unwrap_or_else(|| b"7BIT".to_vec());
	let mut fields = vec![
		string(Some(kind.to_ascii_uppercase().as_bytes())),
		string(Some(subtype.to_ascii_uppercase().as_bytes())),
		params,
		string(raw_header(message, part, HeaderName::ContentId)),
		string(raw_header(message, part, HeaderName::ContentDescription)),
		string(Some(&encoding)),
		body.len().to_string().into_bytes(),
	];
	if kind.eq_ignore_ascii_case("text") {
		fields.push(lines(body));
	} else if kind.eq_ignore_ascii_case("message") && subtype.eq_ignore_ascii_case("rfc822") {
		if let PartType::Message(nested) = &part.body {
			fields.push(envelope::render(nested, 0));
			fields.push(render(nested, 0, extensions));
		} else {
			let nested = super::parse(body);
			fields.push(envelope::render(&nested, 0));
			fields.push(render(&nested, 0, extensions));
		}
		fields.push(lines(body));
	}
	if extensions {
		fields.push(string(raw_header(message, part, HeaderName::ContentMd5)));
		fields.extend(extension_fields(message, part));
	}
	list(fields)
}

fn lines(body: &[u8]) -> Vec<u8> {
	body.iter()
		.filter(|b| **b == b'\n')
		.count()
		.to_string()
		.into_bytes()
}

fn content_type<'a>(
	part: &'a MessagePart<'_>,
	name: HeaderName<'_>,
) -> Option<&'a ContentType<'a>> {
	part.headers.iter().find_map(|h| match &h.value {
		HeaderValue::ContentType(ct) if h.name == name => Some(ct),
		_ => None,
	})
}

fn parameters(ct: Option<&ContentType<'_>>) -> Vec<u8> {
	let Some(attrs) = ct
		.and_then(|ct| ct.attributes.as_ref())
		.filter(|a| !a.is_empty())
	else {
		return b"NIL".to_vec();
	};
	list(attrs.iter().flat_map(|attr| {
		[
			string(Some(attr.name.to_ascii_uppercase().as_bytes())),
			string(Some(attr.value.as_bytes())),
		]
	}))
}

fn extension_fields(message: &Message<'_>, part: &MessagePart<'_>) -> [Vec<u8>; 3] {
	let disposition = content_type(part, HeaderName::ContentDisposition)
		.map(|ct| {
			list([
				string(Some(ct.c_type.to_ascii_uppercase().as_bytes())),
				parameters(Some(ct)),
			])
		})
		.unwrap_or_else(|| b"NIL".to_vec());
	let language = raw_header(message, part, HeaderName::ContentLanguage)
		.map(|v| {
			let values: Vec<_> = v
				.split(|b| *b == b',')
				.map(|s| string(Some(s.trim_ascii())))
				.collect();
			if values.len() == 1 {
				values.into_iter().next().unwrap_or_default()
			} else {
				list(values)
			}
		})
		.unwrap_or_else(|| b"NIL".to_vec());
	[
		disposition,
		language,
		string(raw_header(message, part, HeaderName::ContentLocation)),
	]
}
