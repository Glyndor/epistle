//! JMAP method handlers (RFC 8621): Mailbox and Email objects.

use serde_json::{Value, json};

use super::super::state::ApiState;
use super::objects;

/// `EmailSubmission/set` (RFC 8621 §7.5): queue stored emails for delivery.
pub(super) fn email_submission_set(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	if let Some(create) = args.get("create").and_then(Value::as_object) {
		for (creation_id, submission) in create {
			match submit_email(state, account, submission) {
				Ok(id) => {
					created.insert(creation_id.clone(), json!({ "id": id, "sendAt": null }));
				}
				Err(reason) => {
					not_created.insert(creation_id.clone(), json!({ "type": reason }));
				}
			}
		}
	}
	json!([
		"EmailSubmission/set",
		{ "accountId": account, "oldState": "0", "newState": "0",
		  "created": created, "notCreated": not_created },
		call_id,
	])
}

/// Queue one submission: read its email, build the envelope, spool it.
fn submit_email(
	state: &ApiState,
	account: &str,
	submission: &Value,
) -> Result<String, &'static str> {
	let email_id = submission
		.get("emailId")
		.and_then(Value::as_str)
		.ok_or("invalidProperties")?;
	let raw = objects::find_email_raw(state.data_dir(), account, email_id).ok_or("notFound")?;
	let headers = String::from_utf8_lossy(&raw);
	let envelope = submission.get("envelope");
	let mail_from = envelope
		.and_then(|e| e.get("mailFrom"))
		.and_then(|m| m.get("email"))
		.and_then(Value::as_str)
		.or_else(|| submission.get("identityId").and_then(Value::as_str))
		.unwrap_or("")
		.to_string();
	let recipients: Vec<String> = match envelope
		.and_then(|e| e.get("rcptTo"))
		.and_then(Value::as_array)
	{
		Some(list) => list
			.iter()
			.filter_map(|r| r.get("email").and_then(Value::as_str))
			.map(str::to_string)
			.collect(),
		None => objects::header_value(&headers, "to")
			.map(|to| to.split(',').map(|a| a.trim().to_string()).collect())
			.unwrap_or_default(),
	};
	if recipients.is_empty() {
		return Err("noRecipients");
	}
	let message = crate::smtp::session::AcceptedMessage {
		reverse_path: mail_from,
		recipients,
		data: raw,
		require_tls: false,
		mailbox: None,
	};
	state
		.spool()
		.store(&message)
		.map(|id| id.to_string())
		.map_err(|_| "serverFail")
}

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

/// `Mailbox/set` (RFC 8621 §2.5): create, rename, and delete mailboxes.
pub(super) fn mailbox_set(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let dir = state.data_dir();
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	if let Some(create) = args.get("create").and_then(Value::as_object) {
		for (cid, spec) in create {
			match spec.get("name").and_then(Value::as_str) {
				Some(name) if crate::imap::mailbox::create(dir, account, name).is_ok() => {
					created.insert(cid.clone(), json!({ "id": name }));
				}
				_ => {
					not_created.insert(cid.clone(), json!({ "type": "invalidProperties" }));
				}
			}
		}
	}
	let mut updated = serde_json::Map::new();
	let mut not_updated = serde_json::Map::new();
	if let Some(update) = args.get("update").and_then(Value::as_object) {
		for (id, patch) in update {
			match patch.get("name").and_then(Value::as_str) {
				Some(name) if crate::imap::mailbox::rename(dir, account, id, name).is_ok() => {
					updated.insert(id.clone(), Value::Null);
				}
				_ => {
					not_updated.insert(id.clone(), json!({ "type": "invalidProperties" }));
				}
			}
		}
	}
	let mut destroyed = Vec::new();
	let mut not_destroyed = serde_json::Map::new();
	if let Some(ids) = args.get("destroy").and_then(Value::as_array) {
		for id in ids.iter().filter_map(Value::as_str) {
			if crate::imap::mailbox::delete(dir, account, id).is_ok() {
				destroyed.push(Value::String(id.to_string()));
			} else {
				not_destroyed.insert(id.to_string(), json!({ "type": "notFound" }));
			}
		}
	}
	json!([
		"Mailbox/set",
		{ "accountId": account, "oldState": "0", "newState": "0",
		  "created": created, "notCreated": not_created,
		  "updated": updated, "notUpdated": not_updated,
		  "destroyed": destroyed, "notDestroyed": not_destroyed },
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
		.map(|name| objects::mailbox_object(data_dir, account, &name))
		.collect();

	json!([
		"Mailbox/get",
		{ "accountId": account, "state": "0", "list": list, "notFound": [] },
		call_id,
	])
}

/// `Thread/get` (RFC 8621 §3): each email is its own singleton thread (no
/// server-side threading yet), so a thread's id and its one email id match.
pub(super) fn thread_get(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let mut list = Vec::new();
	let mut not_found = Vec::new();
	if let Some(ids) = args.get("ids").and_then(Value::as_array) {
		for id in ids.iter().filter_map(Value::as_str) {
			if objects::find_email(state.data_dir(), account, id).is_some() {
				list.push(json!({ "id": id, "emailIds": [id] }));
			} else {
				not_found.push(Value::String(id.to_string()));
			}
		}
	}
	json!([
		"Thread/get",
		{ "accountId": account, "state": "0", "list": list, "notFound": not_found },
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
	let mailbox = args
		.get("filter")
		.and_then(|f| f.get("inMailbox"))
		.and_then(Value::as_str)
		.unwrap_or("INBOX");

	let mut ids: Vec<String> =
		crate::imap::mailbox::Snapshot::open(state.data_dir(), account, mailbox)
			.map(|snapshot| snapshot.messages().map(|m| m.id().to_string()).collect())
			.unwrap_or_default();
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
		match objects::find_email(state.data_dir(), account, &id) {
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
