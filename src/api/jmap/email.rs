//! JMAP Email/set and Email/copy: create, update (keywords + mailbox move),
//! destroy, and copy of stored messages (RFC 8621).

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::objects;
use super::state;
use crate::api::api_keys::Scope;

/// `Email/copy` (RFC 8620 section 5.4): copy messages from an accessible
/// source account into the destination account, leaving the source intact.
pub(super) fn email_copy(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	let accounts = state.accounts();
	let Some(destination) = accounts.iter().find(|a| a.name == account) else {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	};
	if !principal.admits_account(&destination.name, &destination.addresses) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let Some(source) = args.get("fromAccountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	let source_view = accounts.iter().find(|a| a.name == source);
	let source_allowed =
		source_view.is_some_and(|view| principal.admits_account(&view.name, &view.addresses));
	if !source_allowed
		|| state
			.require_scope_for_principal(principal, Scope::Read)
			.is_err()
	{
		return json!(["error", { "type": "fromAccountNotFound" }, call_id]);
	}
	let old_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	if let Some(create) = args.get("create").and_then(Value::as_object) {
		for (cid, spec) in create {
			match copy_email(state.data_dir(), source, account, spec, state.crypto()) {
				Ok(info) => {
					created.insert(cid.clone(), info);
				}
				Err(reason) => {
					not_created.insert(cid.clone(), json!({ "type": reason }));
				}
			}
		}
	}
	let new_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	json!([
		"Email/copy",
		{ "fromAccountId": source, "accountId": account,
		  "oldState": old_state, "newState": new_state,
		  "created": created, "notCreated": not_created },
		call_id,
	])
}

/// Copy one message (by `id`) into the target account, keeping the source.
fn copy_email(
	data_dir: &std::path::Path,
	source: &str,
	account: &str,
	spec: &Value,
	crypto: &crate::storage::MessageCrypto,
) -> Result<Value, &'static str> {
	let id = spec.get("id").and_then(Value::as_str).ok_or("notFound")?;
	let target = spec
		.get("mailboxIds")
		.and_then(Value::as_object)
		.and_then(|m| m.iter().find(|(_, v)| v.as_bool() == Some(true)))
		.map(|(name, _)| name.clone())
		.unwrap_or_else(|| "INBOX".to_string());
	let raw = objects::find_email_raw(data_dir, source, id, crypto).ok_or("notFound")?;
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
pub(super) fn email_set(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	uploads: &super::Uploads,
) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	let Some(view) = state.accounts().into_iter().find(|a| a.name == account) else {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	};
	if !principal.admits_account(&view.name, &view.addresses) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let old_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	if let Some(create) = args.get("create").and_then(Value::as_object) {
		for (cid, spec) in create {
			let sources = super::email_build::Sources {
				data_dir: state.data_dir(),
				account,
				crypto: state.crypto(),
				uploads,
			};
			match create_email(spec, &sources, state.max_message_size()) {
				Ok(info) => {
					created.insert(cid.clone(), info);
				}
				Err(error) => {
					not_created.insert(cid.clone(), error);
				}
			}
		}
	}
	let mut updated = serde_json::Map::new();
	let mut not_updated = serde_json::Map::new();
	// One Email/set teaches at most one command's worth of lessons.
	let mut lessons = state
		.training()
		.map(crate::antispam::training_queue::TrainingQueue::command_budget)
		.unwrap_or_default();
	if let Some(update) = args.get("update").and_then(Value::as_object) {
		for (id, patch) in update {
			match apply_email_update(state, account, id, patch, &mut lessons) {
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
	let new_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	json!([
		"Email/set",
		{ "accountId": account, "oldState": old_state, "newState": new_state,
		  "created": created, "notCreated": not_created,
		  "updated": updated, "notUpdated": not_updated,
		  "destroyed": destroyed, "notDestroyed": not_destroyed },
		call_id,
	])
}

/// Create a message from a JMAP Email object (Email/set create): build the
/// RFC 5322 message (RFC 8621 section 4.6) and store it in the target
/// mailbox. The error is the SetError to answer with.
fn create_email(
	spec: &Value,
	sources: &super::email_build::Sources<'_>,
	max_message_size: usize,
) -> Result<Value, Value> {
	let (data_dir, account, crypto) = (sources.data_dir, sources.account, sources.crypto);
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
				out.push(keyword_to_flag(k).map_err(|reason| json!({ "type": reason }))?);
			}
		}
		out
	};
	let raw = super::email_build::build(spec, sources, max_message_size)?;
	let id = crate::imap::mailbox::append(data_dir, account, &mailbox, &flags, &raw, crypto)
		.map_err(|_| json!({ "type": "serverFail" }))?;
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
	lessons: &mut crate::antispam::training_queue::LessonBudget,
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
			(
				message.flags.clone(),
				snapshot.message_path(message).map_err(|_| "serverFail")?,
			)
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
			let new_id = mailbox::append(data_dir, account, target, &flags, &raw, crypto)
				.map_err(|_| "serverFail")?;
			let result = snapshot.remove_at(sequence).map_err(|_| "serverFail");
			// A combined "mark as junk" + "move to Junk" is the natural
			// operation the JMAP client issues, and the source message
			// has already been removed by the time we get here. Replay
			// the transitions against the destination message so the
			// training worker reads the copy that actually carries the new
			// flag set. The path is derived from the new id rather than
			// looked up through the mailbox snapshot (which would race
			// with the rename).
			if let Some(queue) = state.training()
				&& result.is_ok()
			{
				let keyword = patch
					.get("keywords")
					.and_then(|_| crate::imap::junk_trainer::junk_signal(&current_flags, &flags));
				let moved = crate::imap::junk_moves::move_signal(&source, target, true);
				// One message teaches one verdict: the move wins when the
				// two disagree, and nothing is queued twice when they agree.
				if let Some(signal) = moved.or(keyword)
					&& let Some(dir) = mailbox::mailbox_dir(data_dir, account, target)
				{
					crate::imap::junk_moves::enqueue_move(
						queue,
						account,
						signal,
						&dir,
						&[new_id],
						lessons,
					);
				}
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
				crate::imap::junk_trainer::enqueue_junk_transition_within(
					queue,
					account,
					&current_flags,
					updated,
					message_path,
					lessons,
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

#[cfg(test)]
#[path = "copy_tests.rs"]
mod copy_tests;
