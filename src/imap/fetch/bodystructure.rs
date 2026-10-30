//! RFC 9051 MIME tree and extension data.

use super::{ParsedMessage, envelope, list, raw_body, raw_header, string};
use mail_parser::{ContentType, HeaderName, HeaderValue, MessagePart, MessageRef, PartKind};

pub(in crate::imap) fn render(message: &ParsedMessage<'_>, id: usize, extensions: bool) -> Vec<u8> {
	render_at_depth(message, id, extensions, 0)
}

enum Step<'a> {
	Part(MessagePart<'a>, usize),
	Bytes(Vec<u8>),
}

fn render_at_depth(
	message: &ParsedMessage<'_>,
	id: usize,
	extensions: bool,
	depth: usize,
) -> Vec<u8> {
	let mut out = Vec::new();
	let Some(part) = u32::try_from(id).ok().and_then(|id| message.part(id)) else {
		return b"NIL".to_vec();
	};
	let mut pending = vec![Step::Part(part, depth)];
	while let Some(step) = pending.pop() {
		let Step::Part(part, depth) = step else {
			if let Step::Bytes(bytes) = step {
				out.extend(bytes);
			}
			continue;
		};
		if depth >= super::MAX_DEPTH {
			out.extend(opaque(message, &part, extensions));
			continue;
		}
		let ct = content_type(&part, HeaderName::ContentType);
		let (kind, subtype) = ct
			.map(|ct| (ct.ctype(), ct.subtype().unwrap_or("plain")))
			.unwrap_or(match part.kind() {
				PartKind::Message(_) => ("message", "rfc822"),
				_ => ("text", "plain"),
			});
		if part.is_multipart() {
			out.push(b'(');
			let mut suffix = vec![b' '];
			suffix.extend(string(Some(subtype.to_ascii_uppercase().as_bytes())));
			if extensions {
				suffix.push(b' ');
				suffix.extend(parameters(ct));
				for field in extension_fields(part) {
					suffix.push(b' ');
					suffix.extend(field);
				}
			}
			suffix.push(b')');
			pending.push(Step::Bytes(suffix));
			pending.extend(
				part.children()
					.rev()
					.map(|child| Step::Part(child, depth + 1)),
			);
			continue;
		}
		let body = raw_body(message, &part);
		let params = if ct.is_none() && kind == "text" {
			b"(\"CHARSET\" \"US-ASCII\")".to_vec()
		} else {
			parameters(ct)
		};
		let encoding = raw_header(&part, HeaderName::ContentTransferEncoding)
			.map(|v| v.to_ascii_uppercase())
			.unwrap_or_else(|| b"7BIT".to_vec());
		let mut fields = vec![
			string(Some(kind.to_ascii_uppercase().as_bytes())),
			string(Some(subtype.to_ascii_uppercase().as_bytes())),
			params,
			string(raw_header(&part, HeaderName::ContentId)),
			string(raw_header(&part, HeaderName::ContentDescription)),
			string(Some(&encoding)),
			body.len().to_string().into_bytes(),
		];
		if kind.eq_ignore_ascii_case("text") {
			fields.push(lines(body));
		}
		let is_message =
			kind.eq_ignore_ascii_case("message") && subtype.eq_ignore_ascii_case("rfc822");
		if is_message {
			let mut prefix = list(fields);
			prefix.pop();
			prefix.push(b' ');
			if let PartKind::Message(nested) = part.kind() {
				prefix.extend(nested_envelope(nested, depth + 1));
				prefix.push(b' ');
				out.extend(prefix);
				pending.push(Step::Bytes(message_suffix(&part, body, extensions)));
				pending.push(Step::Part(nested.root_part(), depth + 1));
			} else {
				// Carry the same budget through reparsing malformed or encoded bodies.
				let nested = super::parse(body);
				prefix.extend(nested_envelope(nested.root(), depth + 1));
				prefix.push(b' ');
				out.extend(prefix);
				out.extend(render_at_depth(&nested, 0, extensions, depth + 1));
				out.extend(message_suffix(&part, body, extensions));
			}
		} else {
			if extensions {
				fields.push(string(raw_header(&part, HeaderName::ContentMd5)));
				fields.extend(extension_fields(part));
			}
			out.extend(list(fields));
		}
	}
	out
}

fn opaque(message: &ParsedMessage<'_>, part: &MessagePart<'_>, extensions: bool) -> Vec<u8> {
	let mut fields = vec![
		b"\"APPLICATION\"".to_vec(),
		b"\"OCTET-STREAM\"".to_vec(),
		b"NIL".to_vec(),
		b"NIL".to_vec(),
		b"NIL".to_vec(),
		b"\"7BIT\"".to_vec(),
		raw_body(message, part).len().to_string().into_bytes(),
	];
	if extensions {
		fields.push(string(raw_header(part, HeaderName::ContentMd5)));
		fields.extend(extension_fields(*part));
	}
	list(fields)
}

fn nested_envelope(message: MessageRef<'_>, depth: usize) -> Vec<u8> {
	if depth >= super::MAX_DEPTH {
		b"NIL".to_vec()
	} else {
		envelope::render_part(message.root_part())
	}
}

fn message_suffix(part: &MessagePart<'_>, body: &[u8], extensions: bool) -> Vec<u8> {
	let mut fields = vec![lines(body)];
	if extensions {
		fields.push(string(raw_header(part, HeaderName::ContentMd5)));
		fields.extend(extension_fields(*part));
	}
	let mut suffix = list(fields);
	suffix[0] = b' ';
	suffix
}

fn lines(body: &[u8]) -> Vec<u8> {
	body.iter()
		.filter(|b| **b == b'\n')
		.count()
		.to_string()
		.into_bytes()
}

fn content_type<'a>(part: &MessagePart<'a>, name: HeaderName<'_>) -> Option<ContentType<'a>> {
	part.headers()
		.iter()
		.find_map(|header| match header.value() {
			HeaderValue::ContentType(ct) if header.name() == name => Some(ct),
			_ => None,
		})
}

fn parameters(ct: Option<ContentType<'_>>) -> Vec<u8> {
	let Some(ct) = ct else {
		return b"NIL".to_vec();
	};
	let attrs = ct.attributes();
	if attrs.len() == 0 {
		return b"NIL".to_vec();
	}
	list(attrs.flat_map(|(name, value)| {
		[
			string(Some(name.to_ascii_uppercase().as_bytes())),
			string(Some(value.as_bytes())),
		]
	}))
}

fn extension_fields(part: MessagePart<'_>) -> [Vec<u8>; 3] {
	let disposition = content_type(&part, HeaderName::ContentDisposition)
		.map(|ct| {
			list([
				string(Some(ct.ctype().to_ascii_uppercase().as_bytes())),
				parameters(Some(ct)),
			])
		})
		.unwrap_or_else(|| b"NIL".to_vec());
	let language = raw_header(&part, HeaderName::ContentLanguage)
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
		string(raw_header(&part, HeaderName::ContentLocation)),
	]
}
