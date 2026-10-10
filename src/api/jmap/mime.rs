//! MIME part metadata and transfer-decoded octets for JMAP.

use std::borrow::Cow;

use mail_parser::{Message, MessageParser, MessagePart, MimeHeaders, PartType};
use serde_json::{Value, json};

const DEFAULT_PROPERTIES: &[&str] = &[
	"partId",
	"blobId",
	"size",
	"name",
	"type",
	"charset",
	"disposition",
	"cid",
	"language",
	"location",
];

#[path = "mime_body.rs"]
mod body;

#[path = "mime_values.rs"]
mod values;

const MAX_MIME_DEPTH: usize = 64;

struct ParsedMessage<'a>(Message<'a>);

impl<'a> std::ops::Deref for ParsedMessage<'a> {
	type Target = Message<'a>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl Drop for ParsedMessage<'_> {
	fn drop(&mut self) {
		// Unencoded attached messages have no parser depth limit. Detach their
		// children before dropping each message so destruction uses a heap stack.
		let mut pending = std::mem::take(&mut self.0.parts);
		while let Some(part) = pending.pop() {
			if let PartType::Message(mut message) = part.body {
				pending.append(&mut message.parts);
			}
		}
	}
}

fn parse(raw: &[u8]) -> Option<ParsedMessage<'_>> {
	MessageParser::default().parse(raw).map(ParsedMessage)
}

pub(super) fn email_body(id: &str, raw: &[u8], args: &Value) -> Value {
	let Some(message) = parse(raw) else {
		return json!({"bodyStructure":null,"textBody":[],"htmlBody":[],
			"attachments":[],"hasAttachment":false,"preview":"","bodyValues":{}});
	};
	let tree = part_tree(id, &message);
	let (text, html, attachments) = body::lists(&tree);
	let preview = body::preview(&message, &text);
	let mut result = json!({"textBody":text.iter().map(|p| project((*p).clone(),args)).collect::<Vec<_>>(),
		"htmlBody":html.iter().map(|p| project((*p).clone(),args)).collect::<Vec<_>>(),
		"attachments":attachments.iter().map(|p| project((*p).clone(),args)).collect::<Vec<_>>(),
		"hasAttachment":attachments.iter().any(|p| p["disposition"] != "inline"),
		"preview":preview,"bodyValues":values::body_values(&message,&tree,&text,&html,args)});
	result["bodyStructure"] = project(tree, args);
	result
}

fn project(mut value: Value, args: &Value) -> Value {
	let properties = args.get("bodyProperties").and_then(Value::as_array);
	let mut pending = vec![&mut value];
	while let Some(object) = pending.pop().and_then(Value::as_object_mut) {
		object.retain(|name, _| {
			name == "subParts"
				|| properties.map_or_else(
					|| DEFAULT_PROPERTIES.contains(&name.as_str()),
					|properties| properties.iter().any(|p| p.as_str() == Some(name)),
				)
		});
		if let Some(parts) = object.get_mut("subParts").and_then(Value::as_array_mut) {
			pending.extend(parts.iter_mut());
		}
	}
	value
}

/// Only descend through multipart containers, attached messages remain leaves.
/// All subsequent body-list and value walks share this bounded structure.
fn part_tree(id: &str, message: &Message<'_>) -> Value {
	let mut nodes = vec![Value::Null; message.parts.len()];
	let mut pending = vec![(0, "text/plain", 0, false)];
	while let Some((index, implicit, depth, expanded)) = pending.pop() {
		let part = &message.parts[index as usize];
		if expanded {
			nodes[index as usize]["subParts"] = Value::Array(
				part.sub_parts()
					.unwrap_or_default()
					.iter()
					.map(|&child| nodes[child as usize].take())
					.collect(),
			);
			continue;
		}
		let opaque = depth >= MAX_MIME_DEPTH;
		let node = part_metadata(id, message, index, implicit, opaque);
		if node["type"]
			.as_str()
			.is_some_and(|t| t.starts_with("multipart/"))
		{
			let implicit = if node["type"] == "multipart/digest" {
				"message/rfc822"
			} else {
				"text/plain"
			};
			pending.push((index, implicit, depth, true));
			pending.extend(
				part.sub_parts()
					.unwrap_or_default()
					.iter()
					.rev()
					.map(|&child| (child, implicit, depth + 1, false)),
			);
		}
		nodes[index as usize] = node;
	}
	nodes[0].take()
}

fn part_metadata(
	id: &str,
	message: &Message<'_>,
	index: u32,
	implicit: &str,
	opaque: bool,
) -> Value {
	let part = &message.parts[index as usize];
	let media_type = if opaque {
		"application/octet-stream".to_owned()
	} else {
		media_type(part, implicit)
	};
	let multipart = media_type.starts_with("multipart/");
	let charset = media_type.starts_with("text/").then(|| {
		part.content_type()
			.and_then(|ct| ct.attribute("charset"))
			.unwrap_or("us-ascii")
	});
	let language = match part.content_language() {
		mail_parser::HeaderValue::Text(value) => Some(vec![value.as_ref()]),
		mail_parser::HeaderValue::TextList(values) => {
			Some(values.iter().map(|v| v.as_ref()).collect())
		}
		_ => None,
	};
	json!({
		"partId": (!multipart).then(|| index.to_string()),
		"blobId": (!multipart).then(|| format!("{id}.{index}")),
		"size": if multipart { 0 } else { decoded_octets(message, part).len() },
		"name": part.attachment_name().map(crate::util::encoded_word::decode),
		"type": media_type,
		"charset": charset,
		"disposition": part.content_disposition().map(|ct| ct.c_type.to_ascii_lowercase()),
		"cid": part.content_id(), "language": language, "location": part.content_location(),
		"headers": raw_headers(message, part),
	})
}

pub(super) fn media_type(part: &MessagePart<'_>, implicit: &str) -> String {
	part.content_type().map_or_else(
		|| implicit.to_owned(),
		|ct| {
			format!(
				"{}/{}",
				ct.c_type,
				ct.c_subtype.as_deref().unwrap_or("plain")
			)
			.to_ascii_lowercase()
		},
	)
}

/// Keep the original charset octets: MessagePart::contents converts text to UTF-8.
pub(super) fn decoded_octets<'a>(
	message: &'a Message<'_>,
	part: &MessagePart<'_>,
) -> Cow<'a, [u8]> {
	let raw = message
		.raw_message
		.get(part.offset_body as usize..part.offset_end as usize)
		.unwrap_or_default();
	let decoded = match part.content_transfer_encoding().map(str::trim) {
		Some(encoding) if encoding.eq_ignore_ascii_case("base64") => {
			mail_parser::decoders::base64::base64_decode(raw)
		}
		Some(encoding) if encoding.eq_ignore_ascii_case("quoted-printable") => {
			mail_parser::decoders::quoted_printable::quoted_printable_decode(raw)
		}
		_ => None,
	};
	decoded.map_or(Cow::Borrowed(raw), Cow::Owned)
}

fn raw_headers(message: &Message<'_>, part: &MessagePart<'_>) -> Vec<Value> {
	part.headers
		.iter()
		.filter_map(|header| {
			let raw = message
				.raw_message
				.get(header.offset_field as usize..header.offset_end as usize)?;
			let colon = raw.iter().position(|&b| b == b':')?;
			let value = &raw[colon + 1..];
			let value = value
				.strip_suffix(b"\r\n")
				.or_else(|| value.strip_suffix(b"\n"))
				.unwrap_or(value);
			Some(
				json!({"name":String::from_utf8_lossy(&raw[..colon]),"value":String::from_utf8_lossy(value)}),
			)
		})
		.collect()
}

/// Resolve a leaf in the same parser index space used by bodyStructure.
pub(in crate::api::jmap) fn part_blob(raw: &[u8], part_id: &str) -> Option<(String, Vec<u8>)> {
	let index = part_id.parse::<usize>().ok()?;
	if index.to_string() != part_id {
		return None;
	}
	let message = parse(raw)?;
	let mut pending = vec![(0, "text/plain", 0)];
	while let Some((current, implicit, depth)) = pending.pop() {
		let part = message.parts.get(current)?;
		let media_type = if depth >= MAX_MIME_DEPTH {
			"application/octet-stream".to_owned()
		} else {
			media_type(part, implicit)
		};
		let multipart = media_type.starts_with("multipart/");
		if current == index {
			return (!multipart).then(|| (media_type, decoded_octets(&message, part).into_owned()));
		}
		if multipart {
			let implicit = if media_type == "multipart/digest" {
				"message/rfc822"
			} else {
				"text/plain"
			};
			pending.extend(
				part.sub_parts()
					.unwrap_or_default()
					.iter()
					.rev()
					.map(|&child| (child as usize, implicit, depth + 1)),
			);
		}
	}
	None
}
