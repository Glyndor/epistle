//! JMAP method handlers (RFC 8621): Mailbox and Email objects.

use serde_json::{Value, json};

use super::super::state::ApiState;

/// `Identity/get` (RFC 8621 §6.1): the account's sending identities, one per
/// configured address.
pub(super) fn identity_get(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	let Some(view) = state.accounts().into_iter().find(|a| a.name == account) else {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	};
	let list: Vec<Value> = view
		.addresses
		.iter()
		.map(|address| {
			json!({
				"id": address,
				"name": view.name,
				"email": address,
				"replyTo": null,
				"bcc": null,
				"textSignature": "",
				"htmlSignature": "",
				"mayDelete": false,
			})
		})
		.collect();
	json!([
		"Identity/get",
		{ "accountId": account, "state": "0", "list": list, "notFound": [] },
		call_id,
	])
}

/// `Mailbox/get` (RFC 8621 §2.2): return the account's mailboxes as objects.
pub(super) fn mailbox_get(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let data_dir = state.data_dir();
	// Optional `ids` filter: null/absent means all.
	let wanted: Option<Vec<String>> = args
		.get("ids")
		.filter(|v| !v.is_null())
		.and_then(Value::as_array)
		.map(|ids| {
			ids.iter()
				.filter_map(Value::as_str)
				.map(str::to_string)
				.collect()
		});

	let list: Vec<Value> = crate::imap::mailbox::list(data_dir, account)
		.into_iter()
		.filter(|name| wanted.as_ref().is_none_or(|ids| ids.contains(name)))
		.map(|name| mailbox_object(data_dir, account, &name))
		.collect();

	json!([
		"Mailbox/get",
		{ "accountId": account, "state": "0", "list": list, "notFound": [] },
		call_id,
	])
}

/// `Email/query` (RFC 8621 §4.4): the email ids in a mailbox, newest first.
pub(super) fn email_query(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	// Only the `inMailbox` filter is supported; absent means INBOX.
	let mailbox = args
		.get("filter")
		.and_then(|f| f.get("inMailbox"))
		.and_then(Value::as_str)
		.unwrap_or("INBOX");

	let mut ids: Vec<String> =
		crate::imap::mailbox::Snapshot::open(state.data_dir(), account, mailbox)
			.map(|snapshot| snapshot.messages().map(|m| m.id().to_string()).collect())
			.unwrap_or_default();
	// JMAP default sort is most-recent first; UUID v7 ids sort by time.
	ids.reverse();
	let total = ids.len();

	json!([
		"Email/query",
		{
			"accountId": account,
			"queryState": "0",
			"canCalculateChanges": false,
			"position": 0,
			"total": total,
			"ids": ids,
		},
		call_id,
	])
}

/// `Email/get` (RFC 8621 §4.1): return parsed Email objects by id.
pub(super) fn email_get(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let requested: Vec<String> = args
		.get("ids")
		.and_then(Value::as_array)
		.map(|ids| {
			ids.iter()
				.filter_map(Value::as_str)
				.map(str::to_string)
				.collect()
		})
		.unwrap_or_default();

	let mut list = Vec::new();
	let mut not_found = Vec::new();
	for id in requested {
		match find_email(state.data_dir(), account, &id) {
			Some(email) => list.push(email),
			None => not_found.push(Value::String(id)),
		}
	}
	json!([
		"Email/get",
		{ "accountId": account, "state": "0", "list": list, "notFound": not_found },
		call_id,
	])
}

/// `Email/set` (RFC 8621 §4.6): apply keyword updates (mark read/flagged etc.).
/// Only full `keywords` replacement on `update` is supported so far.
pub(super) fn email_set(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let mut updated = serde_json::Map::new();
	let mut not_updated = serde_json::Map::new();
	if let Some(update) = args.get("update").and_then(Value::as_object) {
		for (id, patch) in update {
			match apply_keywords(state.data_dir(), account, id, patch) {
				Ok(()) => {
					updated.insert(id.clone(), Value::Null);
				}
				Err(reason) => {
					not_updated.insert(id.clone(), json!({ "type": reason }));
				}
			}
		}
	}
	let mut destroyed = Vec::new();
	let mut not_destroyed = serde_json::Map::new();
	if let Some(ids) = args.get("destroy").and_then(Value::as_array) {
		for id in ids.iter().filter_map(Value::as_str) {
			match destroy_email(state.data_dir(), account, id) {
				Ok(()) => destroyed.push(Value::String(id.to_string())),
				Err(reason) => {
					not_destroyed.insert(id.to_string(), json!({ "type": reason }));
				}
			}
		}
	}
	json!([
		"Email/set",
		{ "accountId": account, "oldState": "0", "newState": "0",
		  "updated": updated, "notUpdated": not_updated,
		  "destroyed": destroyed, "notDestroyed": not_destroyed },
		call_id,
	])
}

/// Permanently remove a message by id (Email/set destroy).
fn destroy_email(data_dir: &std::path::Path, account: &str, id: &str) -> Result<(), &'static str> {
	let uuid = uuid::Uuid::parse_str(id).map_err(|_| "notFound")?;
	for mailbox in crate::imap::mailbox::list(data_dir, account) {
		let Ok(mut snapshot) = crate::imap::mailbox::Snapshot::open(data_dir, account, &mailbox)
		else {
			continue;
		};
		let position = snapshot.messages().position(|m| m.id() == uuid);
		if let Some(index) = position {
			let sequence = u32::try_from(index + 1).unwrap_or(u32::MAX);
			return snapshot.remove_at(sequence).map_err(|_| "serverFail");
		}
	}
	Err("notFound")
}

/// Apply a `keywords` replacement to a message, mapping JMAP keywords to IMAP
/// flags. Returns a JMAP SetError type string on failure.
fn apply_keywords(
	data_dir: &std::path::Path,
	account: &str,
	id: &str,
	patch: &Value,
) -> Result<(), &'static str> {
	let Some(keywords) = patch.get("keywords").and_then(Value::as_object) else {
		// Only whole-keywords updates are supported (no patch paths yet).
		return Err("invalidPatch");
	};
	let flags: Vec<crate::imap::mailbox::Flag> = keywords
		.iter()
		.filter(|(_, set)| set.as_bool() == Some(true))
		.filter_map(|(keyword, _)| keyword_to_flag(keyword))
		.collect();
	let uuid = uuid::Uuid::parse_str(id).map_err(|_| "notFound")?;
	for mailbox in crate::imap::mailbox::list(data_dir, account) {
		let Ok(mut snapshot) = crate::imap::mailbox::Snapshot::open(data_dir, account, &mailbox)
		else {
			continue;
		};
		let position = snapshot.messages().position(|m| m.id() == uuid);
		if let Some(index) = position {
			let sequence = u32::try_from(index + 1).unwrap_or(u32::MAX);
			return snapshot
				.store_flags(sequence, flags)
				.map(|_| ())
				.map_err(|_| "serverFail");
		}
	}
	Err("notFound")
}

/// Map a JMAP keyword to an IMAP flag, or `None` for unsupported keywords.
fn keyword_to_flag(keyword: &str) -> Option<crate::imap::mailbox::Flag> {
	use crate::imap::mailbox::Flag;
	match keyword {
		"$seen" => Some(Flag::Seen),
		"$answered" => Some(Flag::Answered),
		"$flagged" => Some(Flag::Flagged),
		"$draft" => Some(Flag::Draft),
		_ => None,
	}
}

/// Locate a message by id across the account's mailboxes and build its Email.
fn find_email(data_dir: &std::path::Path, account: &str, id: &str) -> Option<Value> {
	let uuid = uuid::Uuid::parse_str(id).ok()?;
	for mailbox in crate::imap::mailbox::list(data_dir, account) {
		let snapshot = match crate::imap::mailbox::Snapshot::open(data_dir, account, &mailbox) {
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
fn email_object(
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
	let preview: String = headers[body_start..].chars().take(256).collect();

	let mut keywords = serde_json::Map::new();
	for flag in &message.flags {
		if let Some(keyword) = jmap_keyword(*flag) {
			keywords.insert(keyword.to_string(), Value::Bool(true));
		}
	}
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
	})
}

/// First value of a header (case-insensitive), single-line.
fn header_value(headers: &str, name: &str) -> Option<String> {
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
fn address_list(value: Option<&str>) -> Value {
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
fn jmap_keyword(flag: crate::imap::mailbox::Flag) -> Option<&'static str> {
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
fn unix_to_utc(time: std::time::SystemTime) -> String {
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
fn mailbox_object(data_dir: &std::path::Path, account: &str, name: &str) -> Value {
	let (total, unread) = crate::imap::mailbox::Snapshot::open(data_dir, account, name)
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
fn mailbox_role(name: &str) -> Option<&'static str> {
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
