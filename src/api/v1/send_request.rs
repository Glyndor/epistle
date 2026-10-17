//! The JSON body of `POST /api/v1/send` and the header lines its optional
//! fields turn into. Every value that reaches a header is checked here or
//! by the MIME builder; a caller can add the bounded set below and custom
//! `X-` headers, never one that would replace From, To, Date, Message-ID,
//! a signature or the MIME structure.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::api::error::ApiError;
use crate::compose;

/// Most custom `X-` headers one request may add.
const MAX_CUSTOM_HEADERS: usize = 32;

/// Most attachments and inline parts together.
pub(super) const MAX_PARTS: usize = 100;

/// Most message ids in `references`.
const MAX_REFERENCES: usize = 100;

/// Most `List-Unsubscribe` URLs.
const MAX_UNSUBSCRIBE: usize = 4;

/// Most keys in the `extra` correlation map.
pub(super) const MAX_EXTRA_KEYS: usize = 10;

/// Longest single key in the `extra` correlation map, in bytes.
pub(super) const MAX_EXTRA_KEY_LEN: usize = 64;

/// Longest single value in the `extra` correlation map, in bytes.
pub(super) const MAX_EXTRA_VALUE_LEN: usize = 256;

/// `X-` headers the server writes itself from a named field.
const RESERVED_CUSTOM: &[&str] = &["x-priority"];

#[derive(Deserialize)]
pub struct SendRequest {
	pub(super) from: String,
	pub(super) to: Vec<String>,
	#[serde(default)]
	pub(super) cc: Vec<String>,
	/// Envelope only: never written into the message.
	#[serde(default)]
	pub(super) bcc: Vec<String>,
	#[serde(default)]
	pub(super) reply_to: Option<String>,
	#[serde(default)]
	pub(super) subject: String,
	#[serde(default)]
	pub(super) text: Option<String>,
	#[serde(default)]
	pub(super) html: Option<String>,
	/// The sender's name for the `From` header. Absent uses the account's
	/// display name.
	#[serde(default)]
	pub(super) from_name: Option<String>,
	#[serde(default)]
	pub(super) attachments: Vec<PartRequest>,
	/// Parts the HTML refers to by `cid:`; each needs a `content_id`.
	#[serde(default)]
	pub(super) inline: Vec<PartRequest>,
	#[serde(default)]
	pub(super) sender: Option<String>,
	#[serde(default)]
	in_reply_to: Option<String>,
	#[serde(default)]
	references: Option<String>,
	#[serde(default, alias = "priority")]
	importance: Option<String>,
	#[serde(default)]
	list_unsubscribe: Vec<String>,
	#[serde(default)]
	list_unsubscribe_post: bool,
	#[serde(default)]
	auto_submitted: Option<String>,
	#[serde(default)]
	feedback_id: Option<String>,
	/// Custom headers; every name starts with `X-`.
	#[serde(default)]
	headers: BTreeMap<String, String>,
	/// Whether a copy of the message lands in the account's `Sent`
	/// folder. `None` (the default) defers to the account-wide
	/// setting; `Some(false)` disables the save for this request;
	/// `Some(true)` enables it. The per-request override wins over
	/// the account-wide default; nothing here touches the credential
	/// (the credential override is SMTP-only).
	#[serde(default)]
	save_sent: Option<bool>,
	/// Caller-supplied correlation map: at most 10 string keys of at most 64
	/// bytes each and string values of at most 256 bytes, all keys printable
	/// ASCII. The server copies it onto the envelope and the delivery log and
	/// the delivery webhooks, but never writes it into the message itself.
	/// `validated_extra` is what reaches the spool, after the bounds below
	/// are checked.
	#[serde(default)]
	extra: BTreeMap<String, String>,
	/// The class of the message (`transactional`, `marketing`, `personal`).
	/// Absent: the class bound to the API key, else the account default,
	/// else `personal`.
	#[serde(default)]
	class: Option<String>,
}

/// An attachment or inline part: base64 `data`, with the type detected
/// from the bytes and the name when `content_type` is empty.
#[derive(Deserialize)]
pub struct PartRequest {
	#[serde(default)]
	pub(super) name: Option<String>,
	#[serde(default)]
	pub(super) content_type: String,
	pub(super) data: String,
	#[serde(default)]
	pub(super) content_id: Option<String>,
}

impl SendRequest {
	/// Every recipient of the envelope: To, then Cc, then Bcc.
	pub(super) fn recipients(&self) -> Vec<String> {
		self.to
			.iter()
			.chain(&self.cc)
			.chain(&self.bcc)
			.cloned()
			.collect()
	}

	/// The per-request `save_sent` override. `None` means "follow the
	/// account-wide default"; `Some(false)` opts out for this
	/// request; `Some(true)` opts in. The request value always wins
	/// over the account-wide setting, exactly like the SMTP path's
	/// per-request override (which the SMTP path does not have today
	/// but the save-sent logic accommodates).
	pub fn save_sent(&self) -> Option<bool> {
		self.save_sent
	}

	/// The explicit class, refusing a name that is not a class.
	pub(super) fn class(&self) -> Result<Option<crate::evidence::MailClass>, ApiError> {
		match &self.class {
			None => Ok(None),
			Some(name) => crate::evidence::MailClass::parse(name)
				.map(Some)
				.ok_or_else(|| {
					ApiError::invalid_input(
						"Unknown class: use transactional, marketing or personal.",
					)
				}),
		}
	}

	/// The caller-supplied `extra` correlation map, after enforcing its
	/// bounds: at most [`MAX_EXTRA_KEYS`] keys, each at most
	/// [`MAX_EXTRA_KEY_LEN`] bytes of printable ASCII, each value at most
	/// [`MAX_EXTRA_VALUE_LEN`] bytes. The empty default is returned when
	/// the caller did not pass any, and the same map when all entries are
	/// already valid; a request that exceeds any of the bounds is rejected
	/// with the `invalid_input` error the API returns for every malformed
	/// field, so the spool never sees a key or value out of range.
	pub(super) fn validated_extra(&self) -> Result<BTreeMap<String, String>, ApiError> {
		if self.extra.len() > MAX_EXTRA_KEYS {
			return Err(invalid(&format!(
				"extra has {} keys; the maximum is {MAX_EXTRA_KEYS}",
				self.extra.len()
			)));
		}
		for (key, value) in &self.extra {
			if key.len() > MAX_EXTRA_KEY_LEN {
				return Err(invalid(&format!(
					"extra key {key:?} is {} bytes; the maximum is {MAX_EXTRA_KEY_LEN}",
					key.len()
				)));
			}
			if !key.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
				return Err(invalid(&format!(
					"extra key {key:?} must be printable ASCII (no spaces or control characters)"
				)));
			}
			if value.len() > MAX_EXTRA_VALUE_LEN {
				return Err(invalid(&format!(
					"extra value for key {key:?} is {} bytes; the maximum is {MAX_EXTRA_VALUE_LEN}",
					value.len()
				)));
			}
		}
		Ok(self.extra.clone())
	}

	/// Every value that ends up on a header line, for the CR/LF and length
	/// guard.
	pub(super) fn header_bound(&self) -> Vec<&str> {
		let mut fields: Vec<&str> = vec![&self.from, &self.subject];
		fields.extend(
			self.to
				.iter()
				.chain(&self.cc)
				.chain(&self.bcc)
				.map(String::as_str),
		);
		fields.extend(self.list_unsubscribe.iter().map(String::as_str));
		for single in [
			&self.reply_to,
			&self.sender,
			&self.in_reply_to,
			&self.references,
			&self.importance,
			&self.auto_submitted,
			&self.feedback_id,
		] {
			fields.extend(single.as_deref());
		}
		for (name, value) in &self.headers {
			fields.push(name);
			fields.push(value);
		}
		for part in self.attachments.iter().chain(&self.inline) {
			fields.push(&part.content_type);
			fields.extend(part.name.as_deref());
			fields.extend(part.content_id.as_deref());
		}
		fields
	}

	/// The header lines for the optional fields, in the order they are
	/// written, after From, To, Cc and Subject.
	pub(super) fn extra_headers(&self) -> Result<Vec<String>, ApiError> {
		let mut lines = Vec::new();
		if let Some(value) = &self.in_reply_to {
			lines.push(line(compose::structured(
				"In-Reply-To",
				&message_ids(value, 1)?,
			))?);
		}
		if let Some(value) = &self.references {
			let ids = message_ids(value, MAX_REFERENCES)?;
			lines.push(line(compose::structured("References", &ids))?);
		}
		if let Some(value) = &self.importance {
			let (importance, priority) = match value.to_ascii_lowercase().as_str() {
				"high" => ("high", "1 (Highest)"),
				"normal" => ("normal", "3 (Normal)"),
				"low" => ("low", "5 (Lowest)"),
				_ => return Err(invalid("importance must be high, normal or low")),
			};
			lines.push(format!("Importance: {importance}\r\n"));
			lines.push(format!("X-Priority: {priority}\r\n"));
		}
		lines.extend(self.unsubscribe()?);
		if let Some(value) = &self.auto_submitted {
			// RFC 3834 section 5 and RFC 5436.
			let known = ["no", "auto-generated", "auto-replied", "auto-notified"];
			let value = value.to_ascii_lowercase();
			if !known.contains(&value.as_str()) {
				return Err(invalid("auto_submitted is not an RFC 3834 value"));
			}
			lines.push(format!("Auto-Submitted: {value}\r\n"));
		}
		if let Some(value) = &self.feedback_id {
			if value.is_empty() || !value.bytes().all(|b| (0x21..0x7f).contains(&b)) {
				return Err(invalid(
					"feedback_id must be printable ASCII without spaces",
				));
			}
			lines.push(format!("Feedback-ID: {value}\r\n"));
		}
		if self.headers.len() > MAX_CUSTOM_HEADERS {
			return Err(invalid("too many custom headers"));
		}
		for (name, value) in &self.headers {
			if !custom_name(name) {
				return Err(invalid(
					"custom headers must be X- headers the server does not write itself",
				));
			}
			lines.push(line(compose::unstructured(name, value))?);
		}
		Ok(lines)
	}

	/// `List-Unsubscribe` (RFC 2369) and, when asked for, the one-click
	/// `List-Unsubscribe-Post` of RFC 8058, which needs an HTTPS URL.
	fn unsubscribe(&self) -> Result<Vec<String>, ApiError> {
		let urls = &self.list_unsubscribe;
		if urls.is_empty() {
			return match self.list_unsubscribe_post {
				true => Err(invalid("list_unsubscribe_post needs list_unsubscribe")),
				false => Ok(Vec::new()),
			};
		}
		if urls.len() > MAX_UNSUBSCRIBE {
			return Err(invalid("too many list_unsubscribe URLs"));
		}
		let scheme = |url: &str, prefix: &str| {
			url.get(..prefix.len())
				.is_some_and(|head| head.eq_ignore_ascii_case(prefix))
		};
		for url in urls {
			let clean = url
				.bytes()
				.all(|b| (0x21..0x7f).contains(&b) && !b"<>,\"".contains(&b));
			if !clean || !(scheme(url, "mailto:") || scheme(url, "https://")) {
				return Err(invalid("list_unsubscribe takes mailto: and https:// URLs"));
			}
		}
		let bracketed: Vec<String> = urls.iter().map(|url| format!("<{url}>")).collect();
		let mut lines = vec![line(compose::structured(
			"List-Unsubscribe",
			&bracketed.join(", "),
		))?];
		if self.list_unsubscribe_post {
			if !urls.iter().any(|url| scheme(url, "https://")) {
				return Err(invalid("list_unsubscribe_post needs an https:// URL"));
			}
			lines.push("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n".to_string());
		}
		Ok(lines)
	}
}

/// `value` as a list of `<id@domain>` message ids, at most `max` of them,
/// joined by single spaces.
fn message_ids(value: &str, max: usize) -> Result<String, ApiError> {
	let ids: Vec<&str> = value.split_whitespace().collect();
	let valid = |id: &&str| {
		id.len() > 2
			&& id.starts_with('<')
			&& id.ends_with('>')
			&& id[1..id.len() - 1].contains('@')
			&& id[1..id.len() - 1]
				.bytes()
				.all(|b| (0x21..0x7f).contains(&b) && b != b'<' && b != b'>')
	};
	if ids.is_empty() || ids.len() > max || !ids.iter().all(valid) {
		return Err(invalid(
			"in_reply_to and references take <id@domain> message ids",
		));
	}
	Ok(ids.join(" "))
}

/// A custom header name: `X-` and letters, digits and dashes, not one the
/// server writes from its own field.
fn custom_name(name: &str) -> bool {
	name.len() > 2
		&& name.len() <= 76
		&& name[..2].eq_ignore_ascii_case("x-")
		&& name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
		&& !RESERVED_CUSTOM.contains(&name.to_ascii_lowercase().as_str())
}

fn line(result: Result<String, compose::ComposeError>) -> Result<String, ApiError> {
	result.map_err(|error| invalid(&error.to_string()))
}

fn invalid(message: &str) -> ApiError {
	ApiError::invalid_input(&format!("Invalid request: {message}."))
}
