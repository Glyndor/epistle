//! `Email/set` create (RFC 8621 section 4.6): the RFC 5322 message for a
//! JMAP Email object, built with the MIME builder `/api/v1/send` uses.
//!
//! Header values are sanitized as before: a control character collapses to
//! a space, so a client cannot inject a header line, and text outside ASCII
//! is written as RFC 2047 encoded-words. `Content-*` headers belong to the
//! body structure and are refused on the Email itself.

use serde_json::{Value, json};

use super::objects::render_address;
use super::uploads::Uploads;
use crate::compose;
use crate::smtp::trace::ensure_submission_headers;
use crate::util::header::sanitize_header_value;

#[path = "email_build_parts.rs"]
mod parts;

/// Where the parts of one Email come from: the account's uploads read
/// ahead, and its stored messages for a blob id naming a stored part.
pub(super) struct Sources<'a> {
	pub(super) data_dir: &'a std::path::Path,
	pub(super) account: &'a str,
	pub(super) crypto: &'a crate::storage::MessageCrypto,
	pub(super) uploads: &'a Uploads,
}

/// The message for `spec`, or the SetError to answer with.
pub(super) fn build(
	spec: &Value,
	sources: &Sources<'_>,
	max_message_size: usize,
) -> Result<Vec<u8>, Value> {
	refuse_content_headers(spec)?;
	let root = parts::body(spec, sources)?;
	let raw = compose::write(&headers(spec)?, &root).map_err(|_| invalid(&["bodyStructure"]))?;
	if raw.len() > max_message_size {
		return Err(json!({"type": "tooLarge"}));
	}
	let stamp_domain = spec
		.get("from")
		.and_then(Value::as_array)
		.and_then(|list| list.first())
		.and_then(|a| a.get("email"))
		.and_then(Value::as_str)
		.and_then(|email| email.split_once('@').map(|(_, d)| d.to_ascii_lowercase()))
		.unwrap_or_else(|| "localhost".to_string());
	Ok(ensure_submission_headers(
		&raw,
		&stamp_domain,
		std::time::SystemTime::now(),
	))
}

/// The header lines for the Email's address, subject and threading fields.
fn headers(spec: &Value) -> Result<Vec<String>, Value> {
	let mut lines = Vec::new();
	for (property, name) in [
		("from", "From"),
		("sender", "Sender"),
		("to", "To"),
		("cc", "Cc"),
		// Kept on the draft; EmailSubmission/set strips it before sending.
		("bcc", "Bcc"),
		("replyTo", "Reply-To"),
	] {
		let listed: Vec<&Value> = spec
			.get(property)
			.and_then(Value::as_array)
			.into_iter()
			.flatten()
			.collect();
		// `render_address` only strips controls, and the Unicode line and
		// paragraph separators are not controls, so the address parser's
		// refusal of them is repeated here for the structured addresses.
		if listed.iter().any(|addr| {
			addr.get("email")
				.and_then(Value::as_str)
				.is_some_and(crate::util::validation::has_line_separator)
		}) {
			return Err(invalid(&[property]));
		}
		let addresses: Vec<String> = listed.into_iter().filter_map(render_address).collect();
		if !addresses.is_empty() {
			let line = compose::address_list(name, &addresses).map_err(|_| invalid(&[property]))?;
			lines.push(line);
		}
	}
	if let Some(subject) = spec.get("subject").and_then(Value::as_str) {
		let sanitized = sanitize_header_value(subject);
		let line =
			compose::unstructured("Subject", &sanitized).map_err(|_| invalid(&["subject"]))?;
		lines.push(line);
	}
	for (property, name) in [("inReplyTo", "In-Reply-To"), ("references", "References")] {
		let Some(ids) = spec.get(property).filter(|v| !v.is_null()) else {
			continue;
		};
		let ids = message_ids(ids).ok_or_else(|| invalid(&[property]))?;
		let line = compose::structured(name, &ids).map_err(|_| invalid(&[property]))?;
		lines.push(line);
	}
	Ok(lines)
}

/// A JMAP `String[]` of message ids (no angle brackets) as `<a> <b>`.
fn message_ids(ids: &Value) -> Option<String> {
	let list = ids.as_array()?;
	let mut out = Vec::with_capacity(list.len());
	for id in list {
		let id = id.as_str()?;
		let valid = !id.is_empty()
			&& id.len() <= 250
			&& id
				.bytes()
				.all(|b| (0x21..0x7f).contains(&b) && b != b'<' && b != b'>');
		if !valid {
			return None;
		}
		out.push(format!("<{id}>"));
	}
	(!out.is_empty()).then(|| out.join(" "))
}

/// RFC 8621 section 4.6: the Email object itself carries no `Content-*`
/// header, in `headers` or as a `header:Content-*` property; the server
/// writes them from the body structure.
fn refuse_content_headers(spec: &Value) -> Result<(), Value> {
	let Some(object) = spec.as_object() else {
		return Err(invalid(&[]));
	};
	for key in object.keys() {
		if is_content_header(key.strip_prefix("header:").unwrap_or("")) {
			return Err(json!({"type": "invalidProperties", "properties": [key]}));
		}
	}
	if parts::names_header(spec, is_content_header) {
		return Err(invalid(&["headers"]));
	}
	Ok(())
}

fn is_content_header(name: &str) -> bool {
	name.get(..8)
		.is_some_and(|head| head.eq_ignore_ascii_case("content-"))
}

/// The `invalidProperties` SetError naming `properties`.
pub(super) fn invalid(properties: &[&str]) -> Value {
	json!({"type": "invalidProperties", "properties": properties})
}

#[cfg(test)]
#[path = "email_build_tests.rs"]
mod tests;
