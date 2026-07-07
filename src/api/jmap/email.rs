//! JMAP Email/set and Email/copy: create, update (keywords + mailbox move),
//! destroy, and copy of stored messages (RFC 8621).

use serde_json::{Value, json};

use super::super::state::ApiState;
use super::objects;

/// `Email/copy` (RFC 8621 §4.7): copy stored messages into another mailbox of
/// the same account, leaving the source intact. Each `create` entry references
/// an `emailId` and a target `mailboxIds`.
pub(super) fn email_copy(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	if let Some(create) = args.get("create").and_then(Value::as_object) {
		for (cid, spec) in create {
			match copy_email(state.data_dir(), account, spec, state.crypto()) {
				Ok(info) => {
					created.insert(cid.clone(), info);
				}
				Err(reason) => {
					not_created.insert(cid.clone(), json!({ "type": reason }));
				}
			}
		}
	}
	json!([
		"Email/copy",
		{ "fromAccountId": account, "accountId": account,
		  "created": created, "notCreated": not_created },
		call_id,
	])
}

/// Copy one message (by `emailId`) into the target mailbox, keeping the source.
fn copy_email(
	data_dir: &std::path::Path,
	account: &str,
	spec: &Value,
	crypto: &crate::storage::MessageCrypto,
) -> Result<Value, &'static str> {
	let id = spec
		.get("emailId")
		.and_then(Value::as_str)
		.ok_or("notFound")?;
	let target = spec
		.get("mailboxIds")
		.and_then(Value::as_object)
		.and_then(|m| m.iter().find(|(_, v)| v.as_bool() == Some(true)))
		.map(|(name, _)| name.clone())
		.unwrap_or_else(|| "INBOX".to_string());
	let raw = objects::find_email_raw(data_dir, account, id, crypto).ok_or("notFound")?;
	let new_id = crate::imap::mailbox::append(data_dir, account, &target, &[], &raw, crypto)
		.map_err(|_| "serverFail")?;
	Ok(json!({
		"id": new_id.to_string(),
		"blobId": new_id.to_string(),
		"threadId": new_id.to_string(),
		"size": raw.len(),
	}))
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
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	if let Some(create) = args.get("create").and_then(Value::as_object) {
		for (cid, spec) in create {
			match create_email(state.data_dir(), account, spec, state.crypto()) {
				Ok(info) => {
					created.insert(cid.clone(), info);
				}
				Err(reason) => {
					not_created.insert(cid.clone(), json!({ "type": reason }));
				}
			}
		}
	}
	let mut updated = serde_json::Map::new();
	let mut not_updated = serde_json::Map::new();
	if let Some(update) = args.get("update").and_then(Value::as_object) {
		for (id, patch) in update {
			match apply_email_update(state.data_dir(), account, id, patch, state.crypto()) {
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
		  "created": created, "notCreated": not_created,
		  "updated": updated, "notUpdated": not_updated,
		  "destroyed": destroyed, "notDestroyed": not_destroyed },
		call_id,
	])
}

/// Create a message from a JMAP Email object (Email/set create): build an
/// RFC 5322 message and deliver it to the target mailbox.
fn create_email(
	data_dir: &std::path::Path,
	account: &str,
	spec: &Value,
	crypto: &crate::storage::MessageCrypto,
) -> Result<Value, &'static str> {
	let mailbox = spec
		.get("mailboxIds")
		.and_then(Value::as_object)
		.and_then(|m| m.iter().find(|(_, v)| v.as_bool() == Some(true)))
		.map(|(name, _)| name.clone())
		.unwrap_or_else(|| "INBOX".to_string());
	let flags: Vec<crate::imap::mailbox::Flag> = spec
		.get("keywords")
		.and_then(Value::as_object)
		.map(|kw| {
			kw.iter()
				.filter(|(_, v)| v.as_bool() == Some(true))
				.filter_map(|(k, _)| keyword_to_flag(k))
				.collect()
		})
		.unwrap_or_default();
	let raw = objects::build_rfc5322(spec);
	let id = crate::imap::mailbox::append(data_dir, account, &mailbox, &flags, &raw, crypto)
		.map_err(|_| "serverFail")?;
	Ok(json!({
		"id": id.to_string(),
		"blobId": id.to_string(),
		"threadId": id.to_string(),
		"size": raw.len(),
	}))
}

/// Permanently remove a message by id (Email/set destroy).
fn destroy_email(data_dir: &std::path::Path, account: &str, id: &str) -> Result<(), &'static str> {
	let uuid = uuid::Uuid::parse_str(id).map_err(|_| "notFound")?;
	for mailbox in crate::imap::mailbox::list(data_dir, account) {
		let Ok(mut snapshot) = crate::imap::mailbox::Snapshot::open(
			data_dir,
			account,
			&mailbox,
			&crate::storage::MessageCrypto::disabled(),
		) else {
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
fn apply_email_update(
	data_dir: &std::path::Path,
	account: &str,
	id: &str,
	patch: &Value,
	crypto: &crate::storage::MessageCrypto,
) -> Result<(), &'static str> {
	use crate::imap::mailbox::{self, Flag};
	let uuid = uuid::Uuid::parse_str(id).map_err(|_| "notFound")?;
	let target = patch
		.get("mailboxIds")
		.and_then(Value::as_object)
		.and_then(|m| m.iter().find(|(_, v)| v.as_bool() == Some(true)))
		.map(|(name, _)| name.clone());

	for source in mailbox::list(data_dir, account) {
		let Ok(mut snapshot) = mailbox::Snapshot::open(data_dir, account, &source, crypto) else {
			continue;
		};
		let Some(index) = snapshot.messages().position(|m| m.id() == uuid) else {
			continue;
		};
		let sequence = u32::try_from(index + 1).unwrap_or(u32::MAX);
		// Read the bytes and current flags before any mutation.
		let (raw, current_flags) = {
			let message = snapshot.by_sequence(sequence).ok_or("notFound")?;
			(
				snapshot.read(message).map_err(|_| "serverFail")?,
				message.flags.clone(),
			)
		};
		let flags: Vec<Flag> = match patch.get("keywords").and_then(Value::as_object) {
			Some(kw) => kw
				.iter()
				.filter(|(_, set)| set.as_bool() == Some(true))
				.filter_map(|(keyword, _)| keyword_to_flag(keyword))
				.collect(),
			None => current_flags,
		};
		// A different target mailbox means move (append there, drop here).
		if let Some(target) = &target
			&& !target.eq_ignore_ascii_case(&source)
		{
			mailbox::append(data_dir, account, target, &flags, &raw, crypto)
				.map_err(|_| "serverFail")?;
			return snapshot.remove_at(sequence).map_err(|_| "serverFail");
		}
		if patch.get("keywords").is_some() {
			return snapshot
				.store_flags(sequence, flags)
				.map(|_| ())
				.map_err(|_| "serverFail");
		}
		return Ok(());
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
