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
			match apply_email_update(state, account, id, patch) {
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
	let flags: Vec<crate::imap::mailbox::Flag> = {
		let mut out: Vec<crate::imap::mailbox::Flag> = Vec::new();
		if let Some(kw) = spec.get("keywords").and_then(Value::as_object) {
			for (k, v) in kw {
				if v.as_bool() != Some(true) {
					continue;
				}
				out.push(keyword_to_flag(k)?);
			}
		}
		out
	};
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
	state: &ApiState,
	account: &str,
	id: &str,
	patch: &Value,
) -> Result<(), &'static str> {
	use crate::imap::mailbox::{self, Flag};
	let uuid = uuid::Uuid::parse_str(id).map_err(|_| "notFound")?;
	let target = patch
		.get("mailboxIds")
		.and_then(Value::as_object)
		.and_then(|m| m.iter().find(|(_, v)| v.as_bool() == Some(true)))
		.map(|(name, _)| name.clone());

	let data_dir = state.data_dir();
	let crypto = state.crypto();
	for source in mailbox::list(data_dir, account) {
		let Ok(mut snapshot) = mailbox::Snapshot::open(data_dir, account, &source, crypto) else {
			continue;
		};
		let Some(index) = snapshot.messages().position(|m| m.id() == uuid) else {
			continue;
		};
		let sequence = u32::try_from(index + 1).unwrap_or(u32::MAX);
		// Read the current flags and the message path before any mutation.
		// The path is enough for the training worker, which loads the
		// body itself when it drains its job.
		let (current_flags, message_path) = {
			let message = snapshot.by_sequence(sequence).ok_or("notFound")?;
			(message.flags.clone(), snapshot.message_path(message))
		};
		// The raw bytes are still needed if the patch is going to APPEND
		// to another mailbox; the STORE case no longer reads them.
		let raw_for_move: std::io::Result<Vec<u8>> = snapshot
			.by_sequence(sequence)
			.ok_or_else(|| std::io::Error::other("no such message"))
			.and_then(|m| snapshot.read(m));
		let flags: Vec<Flag> = match patch.get("keywords").and_then(Value::as_object) {
			Some(kw) => {
				let mut out: Vec<Flag> = Vec::new();
				for (keyword, set) in kw {
					if set.as_bool() != Some(true) {
						continue;
					}
					out.push(keyword_to_flag(keyword)?);
				}
				// Same per-message cap IMAP STORE / APPEND enforce;
				// refusing here keeps the three paths consistent.
				if mailbox::count_keywords(&out).is_none() {
					return Err("invalidProperties");
				}
				out
			}
			None => current_flags.clone(),
		};
		// A different target mailbox means move (append there, drop here).
		if let Some(target) = &target
			&& !target.eq_ignore_ascii_case(&source)
		{
			let raw = raw_for_move.map_err(|_| "serverFail")?;
			let new_id =
				mailbox::append(data_dir, account, target, &flags, &raw, crypto)
					.map_err(|_| "serverFail")?;
			let result = snapshot.remove_at(sequence).map_err(|_| "serverFail");
			// A combined "mark as junk" + "move to Junk" is the natural
			// operation the JMAP client issues, and the source message
			// has already been removed by the time we get here. Replay
			// the same transition the STORE-only branch runs, against
			// the destination message so the training worker reads the
			// copy that actually carries the new flag set. The path is
			// derived from the new id rather than looked up through the
			// mailbox snapshot (which would race with the rename).
			if patch.get("keywords").is_some()
				&& let Some(queue) = state.training()
			{
				let new_path = mailbox::mailbox_dir(data_dir, account, target)
					.map(|dir| dir.join(format!("{new_id}.eml")))
					.unwrap_or_else(|| message_path.clone());
				crate::imap::junk_trainer::enqueue_junk_transition(
					queue,
					account,
					&current_flags,
					&flags,
					new_path,
				);
			}
			return result;
		}
		if patch.get("keywords").is_some() {
			let updated = snapshot
				.store_flags(sequence, flags)
				.map_err(|_| "serverFail")?;
			// The same decision IMAP STORE takes on a `$Junk` / `$NotJunk`
			// change. The queue never waits, so the reply does not depend
			// on it.
			if let Some(queue) = state.training() {
				crate::imap::junk_trainer::enqueue_junk_transition(
					queue,
					account,
					&current_flags,
					updated,
					message_path,
				);
			}
			return Ok(());
		}
		return Ok(());
	}
	Err("notFound")
}

/// Map a JMAP keyword to an IMAP flag, or `Err` for unsupported keywords.
///
/// The four fixed JMAP keywords (`$seen`, `$answered`, `$flagged`, `$draft`)
/// map to the matching IMAP system flags. Any other `$keyword` token is
/// validated against the IMAP atom rules (see
/// [`crate::imap::keyword::validate`]) and turned into a [`Flag::Keyword`]
/// when valid; an invalid token returns `Err` so the caller can refuse
/// the call with `invalidProperties` rather than silently dropping the
/// flag the client sent.
fn keyword_to_flag(keyword: &str) -> Result<crate::imap::mailbox::Flag, &'static str> {
	use crate::imap::mailbox::Flag;
	match keyword {
		"$seen" => Ok(Flag::Seen),
		"$answered" => Ok(Flag::Answered),
		"$flagged" => Ok(Flag::Flagged),
		"$draft" => Ok(Flag::Draft),
		_ => Flag::parse(keyword).ok_or("invalidProperties"),
	}
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
