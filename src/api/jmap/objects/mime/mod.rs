//! MIME part metadata and transfer-decoded octets for JMAP.

use std::{borrow::Cow, collections::HashMap};

use mail_parser::{Message, MessageParser, MessagePart};
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

mod body;

mod values;

const MAX_MIME_DEPTH: usize = 64;

fn parse(raw: &[u8]) -> Option<Message<'_>> {
	// The JMAP walks below stop at `MAX_MIME_DEPTH` and keep attached messages
	// opaque, so the reader need not nest further (twice the budget plus the
	// root, as one level of theirs can cross a message root and a multipart
	// edge); unbounded, a message
	// nested a hundred thousand deep takes about a minute to parse. The part
	// count stays unbounded as in 0.11, so no attachment is hidden.
	MessageParser::default()
		.max_depth(2 * MAX_MIME_DEPTH + 2)
		.max_parts(usize::MAX)
		.parse(raw)
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
	let parts: Vec<_> = message.root().parts().collect();
	let indices: HashMap<_, _> = parts
		.iter()
		.enumerate()
		.map(|(i, part)| (part.id(), i))
		.collect();
	let mut nodes = vec![Value::Null; parts.len()];
	let mut pending = vec![(0, "text/plain", 0, false)];
	while let Some((index, implicit, depth, expanded)) = pending.pop() {
		let part = &parts[index];
		if expanded {
			nodes[index]["subParts"] = Value::Array(
				part.children()
					.filter_map(|child| indices.get(&child.id()))
					.map(|&child| nodes[child].take())
					.collect(),
			);
			continue;
		}
		let opaque = depth >= MAX_MIME_DEPTH;
		let node = part_metadata(id, part, index, implicit, opaque);
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
				part.children()
					.rev()
					.filter_map(|child| indices.get(&child.id()))
					.map(|&child| (child, implicit, depth + 1, false)),
			);
		}
		nodes[index] = node;
	}
	nodes[0].take()
}

fn part_metadata(
	id: &str,
	part: &MessagePart<'_>,
	index: usize,
	implicit: &str,
	opaque: bool,
) -> Value {
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
	let language = part
		.content_language()
		.map(|values| values.iter().collect::<Vec<_>>());
	json!({
		"partId": (!multipart).then(|| index.to_string()),
		"blobId": (!multipart).then(|| format!("{id}.{index}")),
		"size": if multipart { 0 } else { decoded_octets(part).len() },
		"name": part.attachment_name().map(crate::util::encoded_word::decode),
		"type": media_type,
		"charset": charset,
		"disposition": part.content_disposition().map(|ct| ct.ctype().to_ascii_lowercase()),
		"cid": part.content_id(), "language": language, "location": part.content_location(),
		"headers": raw_headers(part),
	})
}

pub(super) fn media_type(part: &MessagePart<'_>, implicit: &str) -> String {
	part.content_type().map_or_else(
		|| implicit.to_owned(),
		|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("plain")).to_ascii_lowercase(),
	)
}

/// Keep the original charset octets; text() converts them to UTF-8.
pub(super) fn decoded_octets<'a>(part: &MessagePart<'a>) -> Cow<'a, [u8]> {
	let raw = part.raw_body();
	let decoded = match part.content_transfer_encoding().map(str::trim) {
		Some(encoding) if encoding.eq_ignore_ascii_case("base64") => {
			crate::util::mail_parser::base64_decode(raw)
		}
		Some(encoding) if encoding.eq_ignore_ascii_case("quoted-printable") => {
			crate::util::mail_parser::quoted_printable_decode(raw)
		}
		_ => None,
	};
	decoded.map_or(Cow::Borrowed(raw), Cow::Owned)
}

fn raw_headers(part: &MessagePart<'_>) -> Vec<Value> {
	part.headers()
		.iter()
		.filter_map(|header| {
			let raw = part
				.message()
				.source_bytes()
				.get(header.offset_field() as usize..header.offset_end() as usize)?;
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
	let parts: Vec<_> = message.root().parts().collect();
	let indices: HashMap<_, _> = parts
		.iter()
		.enumerate()
		.map(|(i, part)| (part.id(), i))
		.collect();
	let mut pending = vec![(0, "text/plain", 0)];
	while let Some((current, implicit, depth)) = pending.pop() {
		let part = parts.get(current)?;
		let media_type = if depth >= MAX_MIME_DEPTH {
			"application/octet-stream".to_owned()
		} else {
			media_type(part, implicit)
		};
		let multipart = media_type.starts_with("multipart/");
		if current == index {
			return (!multipart).then(|| (media_type, decoded_octets(part).into_owned()));
		}
		if multipart {
			let implicit = if media_type == "multipart/digest" {
				"message/rfc822"
			} else {
				"text/plain"
			};
			pending.extend(
				part.children()
					.rev()
					.filter_map(|child| indices.get(&child.id()))
					.map(|&child| (child, implicit, depth + 1)),
			);
		}
	}
	None
}
