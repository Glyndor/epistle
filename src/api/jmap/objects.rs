//! JMAP object builders: turn stored messages and mailboxes into JMAP
//! Mailbox and Email JSON objects (RFC 8621).

use serde_json::{Value, json};

use super::address_tokenizer::{find_angle_addr, split_top_level};
use crate::smtp::trace::ensure_submission_headers;
use crate::util::encoded_word;
pub(super) use crate::util::header::header_value;
use crate::util::header::sanitize_header_value;

#[path = "mime.rs"]
pub(super) mod mime;

#[cfg(test)]
#[path = "mime_tests_structure.rs"]
mod mime_tests_structure;

/// Serialize a JMAP Email submission object into an RFC 5322 message (Email/set
/// create). Only the common header set and a single text body are emitted.
///
/// `From:`, `To:` and `Subject:` are sanitized through
/// [`sanitize_header_value`] before any encoding: the JMAP spec lets clients
/// submit arbitrary strings for these fields, and a CRLF in any one of them
/// would inject forged headers (Bcc, X-*, …) into the resulting message. The
/// sanitizer collapses every control character to a single space and caps
/// each value to the RFC 5322 998-octet line limit, so a single client
/// submission cannot inflate a single header line past the standard.
///
/// A sanitized value that contains non-ASCII characters is then wrapped in
/// RFC 2047 `=?UTF-8?B?...?=` encoded-words through [`encoded_word::encode`],
/// so the stored message stays ASCII-clean and any reader, IMAP, JMAP, or
/// a hand parser, decodes it back to the original characters.
///
/// `Message-ID` and `Date` are stamped when absent (matching the
/// `EmailSubmission/set` path) so a draft already carries the id a future
/// `EmailSubmission/set` call will queue it with; `domain` is the From
/// address's domain, falling back to `localhost` when the spec had no
/// address. Client-supplied Message-ID / Date are left alone.
pub(super) fn build_rfc5322(spec: &Value) -> Vec<u8> {
	let addresses = |field: &str| -> Option<String> {
		let list = spec.get(field)?.as_array()?;
		let parts: Vec<String> = list.iter().filter_map(render_address).collect();
		(!parts.is_empty()).then(|| parts.join(", "))
	};
	let mut headers = String::new();
	if let Some(from) = addresses("from") {
		headers.push_str(&format!("From: {from}\r\n"));
	}
	if let Some(to) = addresses("to") {
		headers.push_str(&format!("To: {to}\r\n"));
	}
	if let Some(subject) = spec.get("subject").and_then(Value::as_str) {
		let sanitized = sanitize_header_value(subject);
		headers.push_str(&format!(
			"Subject: {}\r\n",
			encoded_word::encode(&sanitized)
		));
	}
	// The body is the first bodyValues entry, else empty.
	let body = spec
		.get("bodyValues")
		.and_then(Value::as_object)
		.and_then(|values| values.values().next())
		.and_then(|part| part.get("value"))
		.and_then(Value::as_str)
		.unwrap_or("");
	headers.push_str("MIME-Version: 1.0\r\n");
	headers.push_str("Content-Type: text/plain; charset=utf-8\r\n");
	let raw = format!("{headers}\r\n{body}").into_bytes();
	let stamp_domain = spec
		.get("from")
		.and_then(Value::as_array)
		.and_then(|list| list.first())
		.and_then(|a| a.get("email"))
		.and_then(Value::as_str)
		.and_then(|email| email.split_once('@').map(|(_, d)| d.to_ascii_lowercase()))
		.unwrap_or_else(|| "localhost".to_string());
	ensure_submission_headers(&raw, &stamp_domain, std::time::SystemTime::now())
}

/// One RFC 5322 address (`"name" <email>` or `<email>`) built from a JMAP
/// address object. The name, when present, is sanitized and then encoded
/// so the stored header is pure ASCII even when the client sent non-ASCII
/// characters. The email is sanitized too, although RFC 5322 already
/// restricts it to ASCII; this keeps the header-injection guard uniform.
fn render_address(addr: &Value) -> Option<String> {
	let email = addr.get("email").and_then(Value::as_str)?;
	let sanitized_email = sanitize_header_value(email);
	if sanitized_email.is_empty() {
		return None;
	}
	let name = addr
		.get("name")
		.and_then(Value::as_str)
		.map(str::trim)
		.filter(|n| !n.is_empty());
	match name {
		Some(raw) => {
			let sanitized = sanitize_header_value(raw);
			let encoded = if sanitized.is_ascii()
				&& sanitized
					.bytes()
					.any(|b| !b.is_ascii_alphanumeric() && !b" !#$%&'*+-/=?^_`{|}~".contains(&b))
			{
				format!(
					"\"{}\"",
					sanitized.replace('\\', "\\\\").replace('"', "\\\"")
				)
			} else {
				encoded_word::encode(&sanitized)
			};
			Some(format!("{encoded} <{sanitized_email}>"))
		}
		None => Some(sanitized_email),
	}
}

/// Raw (plaintext) bytes of a stored message by id, searching the account's
/// mailboxes and decoding the at-rest envelope through `crypto`.
pub(super) fn find_email_raw(
	data_dir: &std::path::Path,
	account: &str,
	id: &str,
	crypto: &crate::storage::MessageCrypto,
) -> Option<Vec<u8>> {
	let uuid = uuid::Uuid::parse_str(id).ok()?;
	for mailbox in crate::imap::mailbox::list(data_dir, account) {
		let Ok(snapshot) =
			crate::imap::mailbox::Snapshot::open(data_dir, account, &mailbox, crypto)
		else {
			continue;
		};
		if let Some(message) = snapshot.messages().find(|m| m.id() == uuid) {
			return snapshot.read(message).ok();
		}
	}
	None
}

/// Locate a message by id across the account's mailboxes and build its Email,
/// decoding the body through `crypto`.
pub(super) fn find_email(
	data_dir: &std::path::Path,
	account: &str,
	id: &str,
	crypto: &crate::storage::MessageCrypto,
	args: &Value,
) -> Option<Value> {
	let uuid = uuid::Uuid::parse_str(id).ok()?;
	for mailbox in crate::imap::mailbox::list(data_dir, account) {
		let snapshot =
			match crate::imap::mailbox::Snapshot::open(data_dir, account, &mailbox, crypto) {
				Ok(snapshot) => snapshot,
				Err(_) => continue,
			};
		if let Some(message) = snapshot.messages().find(|m| m.id() == uuid) {
			let raw = snapshot.read(message).unwrap_or_default();
			return Some(email_object(id, &mailbox, message, &raw, args));
		}
	}
	None
}

/// Build a JMAP Email object from a message and its raw bytes.
pub(super) fn email_object(
	id: &str,
	mailbox: &str,
	message: &crate::imap::mailbox::MessageRef,
	raw: &[u8],
	args: &Value,
) -> Value {
	let headers = String::from_utf8_lossy(raw);
	let header = |name: &str| header_value(&headers, name);
	let mime = mime::email_body(id, raw, args);

	let mut keywords = serde_json::Map::new();
	for flag in &message.flags {
		if let Some(keyword) = jmap_keyword(flag) {
			keywords.insert(keyword, Value::Bool(true));
		}
	}

	let mut email = json!({
		"id": id,
		"blobId": id,
		"threadId": id,
		"mailboxIds": { mailbox: true },
		"keywords": keywords,
		"size": message.size,
		"receivedAt": unix_to_utc(message.internal_date),
		"subject": header("subject").map(|s| encoded_word_decode_subject(&s)),
		"from": address_list(header("from").as_deref()),
		"to": address_list(header("to").as_deref()),
		"messageId": header("message-id").map(|m| vec![m]),
	});
	// Move the bounded MIME tree without recursively serializing it again.
	if let (Some(email), Value::Object(mime)) = (email.as_object_mut(), mime) {
		email.extend(mime);
	}
	email
}

/// Decode the `Subject:` for a JMAP `Email/subject` value. `Subject:` is a
/// single unstructured header, so the entire value goes through
/// [`encoded_word::decode`] in one pass.
fn encoded_word_decode_subject(value: &str) -> String {
	encoded_word::decode(value)
}

/// A JMAP address list `[{name, email}]` from a header value. The parser
/// is address-list aware: a top-level comma separates addresses, but commas
/// inside `<...>`, inside a quoted-string, or inside a `=?...?=` encoded
/// word do not. Decoding the display name happens AFTER the split, so an
/// encoded-word that decodes to a value containing `<`, `>`, CR or LF
/// cannot inject a second address (the byte it expands to is data, never a
/// delimiter).
pub(super) fn address_list(value: Option<&str>) -> Value {
	match value {
		Some(v) => {
			let parsed = parse_address_list(v);
			Value::Array(parsed.into_iter().map(jmap_address).collect())
		}
		None => Value::Null,
	}
}

fn jmap_address(parsed: ParsedAddress) -> Value {
	let name = match parsed.name {
		Some(name) => {
			// Decoding happens AFTER the address-list split: an encoded-word
			// whose payload contains `<`, `>`, `,` or CR/LF cannot inject a
			// second address because the parser only saw the raw bytes.
			let decoded = decode_display_name(&name);
			let trimmed = decoded.trim();
			if trimmed.is_empty() {
				Value::Null
			} else {
				Value::String(trimmed.to_string())
			}
		}
		None => Value::Null,
	};
	json!({ "name": name, "email": parsed.email })
}

fn decode_display_name(name: &str) -> String {
	if let Some(quoted) = name.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
		let mut decoded = String::with_capacity(quoted.len());
		let mut chars = quoted.chars();
		while let Some(c) = chars.next() {
			if c == '\\' {
				if let Some(escaped) = chars.next() {
					decoded.push(escaped);
				}
			} else {
				decoded.push(c);
			}
		}
		decoded
	} else {
		encoded_word::decode(name)
	}
}

/// One parsed address from an RFC 5322 address-list header value.
struct ParsedAddress {
	name: Option<String>,
	email: String,
}

/// Split a header value into individual addresses at top-level commas,
/// then peel off the angle-addr (the `<...>` portion, which holds the
/// actual email) and the leading phrase (the display name). The
/// tokenizer that splits at top-level commas and locates the
/// angle-addr lives in [`super::address_tokenizer`] so the parser and
/// its work counter can evolve independently.
fn parse_address_list(value: &str) -> Vec<ParsedAddress> {
	let parts = split_top_level(value, ',');
	parts
		.into_iter()
		.map(|raw| parse_address(&raw))
		.filter(|addr| !addr.email.is_empty())
		.collect()
}

// One address: extract the angle-addr email if present, otherwise treat
// the whole value as the email. Everything before the last `<` is the
// display name, when an angle-addr was found.
fn parse_address(raw: &str) -> ParsedAddress {
	let trimmed = raw.trim();
	if let Some((open, close)) = find_angle_addr(trimmed) {
		let email = trimmed[open + 1..close].trim().to_string();
		let name = trimmed[..open].trim().to_string();
		return ParsedAddress {
			name: (!name.is_empty()).then_some(name),
			email,
		};
	}
	ParsedAddress {
		name: None,
		email: trimmed.to_string(),
	}
}

/// Map an IMAP flag to its JMAP keyword (RFC 8621 §4.1.1).
///
/// The four system flags map to the matching JMAP keywords. Any
/// user-defined keyword is rendered as its own `$keyword` token so
/// custom flags survive the Email/get round-trip. `\Deleted` is
/// intentionally not mapped (JMAP uses a separate `isDeleted` boolean).
pub(super) fn jmap_keyword(flag: &crate::imap::mailbox::Flag) -> Option<String> {
	use crate::imap::mailbox::Flag;
	match flag {
		Flag::Seen => Some("$seen".to_string()),
		Flag::Answered => Some("$answered".to_string()),
		Flag::Flagged => Some("$flagged".to_string()),
		Flag::Draft => Some("$draft".to_string()),
		Flag::Deleted => None,
		Flag::Keyword(keyword) => Some(keyword.as_str().to_string()),
	}
}

/// Format a `SystemTime` as a JMAP UTCDate (`YYYY-MM-DDThh:mm:ssZ`).
pub(super) fn unix_to_utc(time: std::time::SystemTime) -> String {
	let secs = time
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let days = (secs / 86_400) as i64;
	let (h, mi, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
	let z = days + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = doy - (153 * mp + 2) / 5 + 1;
	let month = if mp < 10 { mp + 3 } else { mp - 9 };
	let year = yoe + era * 400 + i64::from(month <= 2);
	format!("{year:04}-{month:02}-{day:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Build one JMAP Mailbox object from a mailbox name.
pub(super) fn mailbox_object(data_dir: &std::path::Path, account: &str, name: &str) -> Value {
	let (total, unread) = crate::imap::mailbox::Snapshot::open(
		data_dir,
		account,
		name,
		&crate::storage::MessageCrypto::disabled(),
	)
	.map(|snapshot| {
		let unread = snapshot
			.messages()
			.filter(|m| !m.flags.contains(&crate::imap::mailbox::Flag::Seen))
			.count();
		(snapshot.len(), unread)
	})
	.unwrap_or((0, 0));
	json!({
		"id": name,
		"name": name,
		"parentId": null,
		"role": mailbox_role(name),
		"sortOrder": 0,
		"totalEmails": total,
		"unreadEmails": unread,
		"totalThreads": total,
		"unreadThreads": unread,
		"isSubscribed": true,
		"myRights": {
			"mayReadItems": true, "mayAddItems": true, "mayRemoveItems": true,
			"maySetSeen": true, "maySetKeywords": true, "mayCreateChild": false,
			"mayRename": false, "mayDelete": false, "maySubmit": true,
		},
	})
}

/// Map a mailbox name to a JMAP role (RFC 8621 §2), or null.
pub(super) fn mailbox_role(name: &str) -> Option<&'static str> {
	match name.to_ascii_lowercase().as_str() {
		"inbox" => Some("inbox"),
		"sent" => Some("sent"),
		"drafts" => Some("drafts"),
		"junk" | "spam" | "rejects" => Some("junk"),
		"trash" => Some("trash"),
		"archive" => Some("archive"),
		_ => None,
	}
}

#[cfg(test)]
#[path = "objects_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "mime_tests_body.rs"]
mod mime_tests_body;

#[cfg(test)]
#[path = "mime_tests_values.rs"]
mod mime_tests_values;

#[cfg(test)]
#[path = "mime_tests_download.rs"]
mod mime_tests_download;

#[cfg(test)]
#[path = "mime_tests_depth.rs"]
mod mime_tests_depth;

#[cfg(test)]
#[path = "objects_tests_default_mailboxes.rs"]
mod default_mailboxes;
