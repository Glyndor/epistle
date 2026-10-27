//! The body of an `Email/set` create: from `textBody`, `htmlBody` and
//! `attachments`, or from an explicit `bodyStructure`, with text from
//! `bodyValues` and octets from uploaded blobs or stored messages.

use serde_json::{Value, json};

use super::super::uploads::Found;
use super::{Sources, invalid};
use crate::compose::{self, Bodies, Content, Disposition, Leaf, Part};

/// Deepest `bodyStructure` accepted.
const MAX_DEPTH: usize = 16;

/// True when `part` lists a header whose name `matches` in `headers` or
/// as a `header:<name>` property.
pub(super) fn names_header(part: &Value, matches: fn(&str) -> bool) -> bool {
	let listed = part
		.get("headers")
		.and_then(Value::as_array)
		.into_iter()
		.flatten()
		.filter_map(|header| header.get("name").and_then(Value::as_str))
		.any(matches);
	let property = part.as_object().is_some_and(|object| {
		object
			.keys()
			.filter_map(|key| key.strip_prefix("header:"))
			.any(|name| matches(name.split(':').next().unwrap_or("")))
	});
	listed || property
}

/// The body of `spec` as one part.
pub(super) fn body(spec: &Value, sources: &Sources<'_>) -> Result<Part, Value> {
	let given = |key: &str| spec.get(key).is_some_and(|value| !value.is_null());
	let values = spec.get("bodyValues");
	let listed = given("textBody") || given("htmlBody") || given("attachments");
	if given("bodyStructure") {
		if listed {
			return Err(invalid(&["bodyStructure"]));
		}
		return structure(&spec["bodyStructure"], values, sources, 0);
	}
	if !listed {
		// No structure at all: the first body value as plain text, as this
		// server has always written it.
		let text = values
			.and_then(Value::as_object)
			.and_then(|values| values.values().next())
			.and_then(|part| part.get("value"))
			.and_then(Value::as_str)
			.unwrap_or("");
		return Ok(Part::Leaf(Leaf::text("plain", text)));
	}
	let mut bodies = Bodies {
		text: single(spec, "textBody", "text/plain", sources)?,
		html: single(spec, "htmlBody", "text/html", sources)?,
		..Bodies::default()
	};
	let attachments = spec.get("attachments").filter(|v| !v.is_null());
	if attachments.is_some_and(|list| !list.is_array()) {
		return Err(invalid(&["attachments"]));
	}
	for part in attachments.and_then(Value::as_array).into_iter().flatten() {
		let leaf = leaf(
			part,
			values,
			sources,
			Some(Disposition::Attachment),
			"attachments",
		)?;
		// RFC 8621 section 4.6: inline parts with a cid sit beside the HTML.
		if bodies.html.is_some()
			&& leaf.disposition == Some(Disposition::Inline)
			&& leaf.content_id.is_some()
		{
			bodies.inline.push(leaf);
		} else {
			bodies.attachments.push(leaf);
		}
	}
	Ok(bodies.assemble())
}

/// `textBody` or `htmlBody`: at most one part, of type `kind`.
fn single(
	spec: &Value,
	property: &str,
	kind: &str,
	sources: &Sources<'_>,
) -> Result<Option<Leaf>, Value> {
	let Some(list) = spec.get(property).filter(|v| !v.is_null()) else {
		return Ok(None);
	};
	match list.as_array().map(Vec::as_slice) {
		Some([]) => Ok(None),
		Some([part]) => {
			let given = part.get("type").and_then(Value::as_str);
			if given.is_some_and(|given| !given.eq_ignore_ascii_case(kind)) {
				return Err(invalid(&[property]));
			}
			let mut leaf = leaf(part, spec.get("bodyValues"), sources, None, property)?;
			if given.is_none() && matches!(leaf.content, Content::Text(_)) {
				leaf.content_type = kind.to_string();
			}
			Ok(Some(leaf))
		}
		_ => Err(invalid(&[property])),
	}
}

/// An explicit `bodyStructure` node and everything under it.
fn structure(
	node: &Value,
	values: Option<&Value>,
	sources: &Sources<'_>,
	depth: usize,
) -> Result<Part, Value> {
	if depth > MAX_DEPTH {
		return Err(invalid(&["bodyStructure"]));
	}
	let Some(sub_parts) = node.get("subParts").filter(|v| !v.is_null()) else {
		return leaf(node, values, sources, None, "bodyStructure").map(Part::Leaf);
	};
	let kind = node
		.get("type")
		.and_then(Value::as_str)
		.unwrap_or("multipart/mixed")
		.to_ascii_lowercase();
	let subtype = kind.strip_prefix("multipart/");
	let has_content = node.get("partId").is_some() || node.get("blobId").is_some();
	let (Some(subtype), Some(list), false) = (subtype, sub_parts.as_array(), has_content) else {
		return Err(invalid(&["bodyStructure"]));
	};
	let mut parts = Vec::with_capacity(list.len());
	for sub in list {
		parts.push(structure(sub, values, sources, depth + 1)?);
	}
	Ok(compose::multipart(subtype, parts))
}

/// One leaf: text from `bodyValues` by `partId`, or octets by `blobId`.
fn leaf(
	part: &Value,
	values: Option<&Value>,
	sources: &Sources<'_>,
	default_disposition: Option<Disposition>,
	property: &str,
) -> Result<Leaf, Value> {
	// RFC 8621 section 4.6: the server picks the transfer encoding.
	if names_header(part, |name| {
		name.eq_ignore_ascii_case("content-transfer-encoding")
	}) {
		return Err(invalid(&[property]));
	}
	let text = |key: &str| part.get(key).and_then(Value::as_str);
	let name = text("name").map(str::to_string);
	let (content, content_type) = match (text("partId"), text("blobId")) {
		(Some(part_id), None) => {
			let kind = text("type").unwrap_or("text/plain").to_ascii_lowercase();
			let charset = part.get("charset").is_some_and(|v| !v.is_null());
			if charset || !kind.starts_with("text/") {
				return Err(invalid(&[property]));
			}
			let value = values
				.and_then(|values| values.get(part_id))
				.ok_or_else(|| invalid(&["bodyValues"]))?;
			let flagged = |key: &str| value.get(key).and_then(Value::as_bool) == Some(true);
			let text = value.get("value").and_then(Value::as_str);
			match text {
				Some(text) if !flagged("isTruncated") && !flagged("isEncodingProblem") => {
					(Content::Text(text.to_string()), kind)
				}
				_ => return Err(invalid(&["bodyValues"])),
			}
		}
		(None, Some(blob_id)) => {
			let (recorded, data) = blob(blob_id, sources)?;
			let kind = text("type")
				.map(str::to_string)
				.or(recorded)
				.unwrap_or_else(|| compose::content_type_for(name.as_deref(), &data).to_string());
			(Content::Bytes(data), kind)
		}
		_ => return Err(invalid(&[property])),
	};
	let disposition = match part.get("disposition").and_then(Value::as_str) {
		None => default_disposition,
		Some(value) if value.eq_ignore_ascii_case("attachment") => Some(Disposition::Attachment),
		Some(value) if value.eq_ignore_ascii_case("inline") => Some(Disposition::Inline),
		Some(_) => return Err(invalid(&[property])),
	};
	Ok(Leaf {
		content_type,
		content,
		disposition,
		name,
		content_id: text("cid").map(str::to_string),
	})
}

/// The octets of `blob_id` and its recorded type: an upload read ahead,
/// else a stored message or one of its parts (`<message id>.<part id>`).
fn blob(blob_id: &str, sources: &Sources<'_>) -> Result<(Option<String>, Vec<u8>), Value> {
	match sources.uploads.find(sources.account, blob_id) {
		Found::Blob(upload) => {
			let recorded = upload
				.content_type
				.clone()
				.filter(|kind| kind != "application/octet-stream");
			return Ok((recorded, upload.data.clone()));
		}
		Found::OverBudget => return Err(json!({"type": "tooLarge"})),
		Found::Missing => {}
	}
	let (message_id, part_id) = match blob_id.split_once('.') {
		Some((message, part)) => (message, Some(part)),
		None => (blob_id, None),
	};
	let stored = super::super::objects::find_email_raw(
		sources.data_dir,
		sources.account,
		message_id,
		sources.crypto,
	)
	.and_then(|raw| match part_id {
		Some(part_id) => super::super::objects::mime::part_blob(&raw, part_id),
		None => Some(("message/rfc822".to_string(), raw)),
	});
	match stored {
		Some((kind, data)) => Ok((Some(kind), data)),
		None => Err(json!({"type": "blobNotFound", "notFound": [blob_id]})),
	}
}
