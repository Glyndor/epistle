//! JMAP object builders: turn stored messages and mailboxes into JMAP
//! Mailbox and Email JSON objects (RFC 8621).

use serde_json::{Value, json};

/// Serialize a JMAP Email submission object into an RFC 5322 message (Email/set
/// create). Only the common header set and a single text body are emitted.
pub(super) fn build_rfc5322(spec: &Value) -> Vec<u8> {
	let addresses = |field: &str| -> Option<String> {
		let list = spec.get(field)?.as_array()?;
		let joined: Vec<String> = list
			.iter()
			.filter_map(|a| a.get("email").and_then(Value::as_str).map(str::to_string))
			.collect();
		(!joined.is_empty()).then(|| joined.join(", "))
	};
	let mut headers = String::new();
	if let Some(from) = addresses("from") {
		headers.push_str(&format!("From: {from}\r\n"));
	}
	if let Some(to) = addresses("to") {
		headers.push_str(&format!("To: {to}\r\n"));
	}
	if let Some(subject) = spec.get("subject").and_then(Value::as_str) {
		headers.push_str(&format!("Subject: {subject}\r\n"));
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
	format!("{headers}\r\n{body}").into_bytes()
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
			return Some(email_object(id, &mailbox, message, &raw));
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
) -> Value {
	let headers = String::from_utf8_lossy(raw);
	let header = |name: &str| header_value(&headers, name);
	let body_start = headers
		.find("\r\n\r\n")
		.map(|p| p + 4)
		.unwrap_or(headers.len());
	let body = &headers[body_start..];
	let preview: String = body.chars().take(256).collect();

	let mut keywords = serde_json::Map::new();
	for flag in &message.flags {
		if let Some(keyword) = jmap_keyword(*flag) {
			keywords.insert(keyword.to_string(), Value::Bool(true));
		}
	}
	// One text/plain body part (no MIME structure parsing yet); the body text
	// is exposed in bodyValues under part id "0".
	let part = json!({ "partId": "0", "blobId": id, "size": body.len(), "type": "text/plain" });
	json!({
		"id": id,
		"blobId": id,
		"threadId": id,
		"mailboxIds": { mailbox: true },
		"keywords": keywords,
		"size": message.size,
		"receivedAt": unix_to_utc(message.internal_date),
		"subject": header("subject"),
		"from": address_list(header("from").as_deref()),
		"to": address_list(header("to").as_deref()),
		"messageId": header("message-id").map(|m| vec![m]),
		"preview": preview.trim(),
		"bodyStructure": part,
		"textBody": [part],
		"htmlBody": [part],
		"bodyValues": { "0": { "value": body, "isEncodingProblem": false, "isTruncated": false } },
	})
}

/// First value of a header (case-insensitive), single-line.
pub(super) fn header_value(headers: &str, name: &str) -> Option<String> {
	for line in headers.lines() {
		if line.is_empty() {
			break;
		}
		if let Some((key, value)) = line.split_once(':')
			&& key.trim().eq_ignore_ascii_case(name)
		{
			return Some(value.trim().to_string());
		}
	}
	None
}

/// A JMAP address list `[{name, email}]` from a header value (addresses only).
pub(super) fn address_list(value: Option<&str>) -> Value {
	match value {
		Some(v) => Value::Array(
			v.split(',')
				.map(|addr| json!({ "name": null, "email": addr.trim() }))
				.collect(),
		),
		None => Value::Null,
	}
}

/// Map an IMAP flag to its JMAP keyword (RFC 8621 §4.1.1).
pub(super) fn jmap_keyword(flag: crate::imap::mailbox::Flag) -> Option<&'static str> {
	use crate::imap::mailbox::Flag;
	match flag {
		Flag::Seen => Some("$seen"),
		Flag::Answered => Some("$answered"),
		Flag::Flagged => Some("$flagged"),
		Flag::Draft => Some("$draft"),
		Flag::Deleted => None,
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
		"junk" | "spam" => Some("junk"),
		"trash" => Some("trash"),
		"archive" => Some("archive"),
		_ => None,
	}
}
