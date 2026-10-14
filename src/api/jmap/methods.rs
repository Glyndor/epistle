//! JMAP method handlers (RFC 8621): Mailbox and Email objects.
//!
//! The `/changes` and `/queryChanges` dispatch helpers live in
//! [`super::state`]; this file holds the shape-by-shape method handlers
//! (Mailbox/get/query, Email/get/query, Thread/get, EmailSubmission/set,
//! Identity/get, Quota/get). Mailbox/set lives in [`super::mailbox_set`]. Submission and identity helpers split out
//! into sibling files so this one stays under the per-file line cap.

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::objects;
use super::state;
use crate::util::mailbox_path;

/// `Quota/get` (RFC 9425): the account's storage quota in octets.
pub(super) fn quota_get(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
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
	let used = crate::imap::mailbox::account_usage(state.data_dir(), account, state.crypto());
	let limit = state.quota_for_account(account);
	let mut quota = serde_json::Map::from_iter([
		("id".to_string(), json!("mail")),
		("resourceType".to_string(), json!("octets")),
		("used".to_string(), json!(used)),
		("scope".to_string(), json!("account")),
		("name".to_string(), json!("Mail storage")),
		("types".to_string(), json!(["Mail"])),
	]);
	// The limit in force is the hard limit; no limit (a quota of 0) is
	// omitted.
	quota.insert(
		"limit".to_string(),
		limit.map_or(Value::Null, |limit| json!(limit)),
	);
	let quota_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	json!([
		"Quota/get",
		{ "accountId": account, "state": quota_state, "list": [quota], "notFound": [] },
		call_id,
	])
}

/// `Identity/get` (RFC 8621 §6.1): the account's sending identities, one per
/// configured address. `name` is the account's display name, or empty when it
/// has none (RFC 8621 allows an empty name; the account identifier is not a
/// person's name).
pub(super) fn identity_get(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
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
	let list: Vec<Value> = view
		.addresses
		.iter()
		.map(|address| {
			json!({
				"id": address,
				"name": view.display_name.as_deref().unwrap_or_default(),
				"email": address,
				"replyTo": null,
				"bcc": null,
				"textSignature": "",
				"htmlSignature": "",
				"mayDelete": false,
			})
		})
		.collect();
	let identity_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	json!([
		"Identity/get",
		{ "accountId": account, "state": identity_state, "list": list, "notFound": [] },
		call_id,
	])
}

/// `Mailbox/get` (RFC 8621 §2.2): return the account's mailboxes as objects.
pub(super) fn mailbox_get(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
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

	let names = crate::imap::mailbox::list(data_dir, account);
	// `ids: null` returns every mailbox only while there are no more than
	// `maxObjectsInGet` of them (RFC 8620 §5.1).
	if wanted.is_none() && names.len() > super::limits::MAX_OBJECTS_IN_GET {
		return json!(["error", { "type": "requestTooLarge" }, call_id]);
	}
	let existing: std::collections::HashSet<&str> = names.iter().map(String::as_str).collect();
	let list: Vec<Value> = names
		.iter()
		.filter(|name| wanted.as_ref().is_none_or(|ids| ids.contains(name)))
		.map(|name| {
			let parent = mailbox_path::nearest_parent(name, |other| existing.contains(other));
			objects::mailbox_object(data_dir, account, name, parent)
		})
		.collect();

	let mailbox_state =
		state::mailbox_get_state(data_dir, account).unwrap_or_else(|| "0".to_string());
	json!([
		"Mailbox/get",
		{ "accountId": account, "state": mailbox_state, "list": list, "notFound": [] },
		call_id,
	])
}

/// `Thread/get` (RFC 8621 §3): each email is its own singleton thread (no
/// server-side threading yet), so a thread's id and its one email id match.
pub(super) fn thread_get(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
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
	let mut list = Vec::new();
	let mut not_found = Vec::new();
	if let Some(ids) = args.get("ids").and_then(Value::as_array) {
		for id in ids.iter().filter_map(Value::as_str) {
			if objects::find_email(state.data_dir(), account, id, state.crypto(), &Value::Null)
				.is_some()
			{
				list.push(json!({ "id": id, "emailIds": [id] }));
			} else {
				not_found.push(Value::String(id.to_string()));
			}
		}
	}
	let thread_state =
		state::thread_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	json!([
		"Thread/get",
		{ "accountId": account, "state": thread_state, "list": list, "notFound": not_found },
		call_id,
	])
}

/// `Mailbox/query` (RFC 8621 §2.3): the account's mailbox ids, sorted by name.
pub(super) fn mailbox_query(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
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
	let ids: Vec<String> = crate::imap::mailbox::list(state.data_dir(), account);
	let total = ids.len();
	let query_state =
		state::mailbox_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	json!([
		"Mailbox/query",
		{
			"accountId": account,
			"queryState": query_state,
			"canCalculateChanges": true,
			"position": 0,
			"total": total,
			"ids": ids,
		},
		call_id,
	])
}

/// `Email/query` (RFC 8621 §4.4): the email ids in a mailbox, newest first.
pub(super) fn email_query(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
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
	let mailbox = args
		.get("filter")
		.and_then(|f| f.get("inMailbox"))
		.and_then(Value::as_str)
		.unwrap_or("INBOX");
	let ids = super::query_changes::email_query_ids(state, account, mailbox);
	let total = ids.len();
	let query_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	// Only the query shapes `Email/queryChanges` can replay exactly.
	let can_calculate = super::query_changes::replayable_email_query(args).is_some();

	json!([
		"Email/query",
		{
			"accountId": account,
			"queryState": query_state,
			"canCalculateChanges": can_calculate,
			"position": 0,
			"total": total,
			"ids": ids,
		},
		call_id,
	])
}

/// `Email/get` (RFC 8621 §4.1): return parsed Email objects by id.
pub(super) fn email_get(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
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
		match objects::find_email(state.data_dir(), account, &id, state.crypto(), args) {
			Some(email) => list.push(email),
			None => not_found.push(Value::String(id)),
		}
	}
	let email_state =
		state::email_get_state(state.data_dir(), account).unwrap_or_else(|| "0".to_string());
	json!([
		"Email/get",
		{ "accountId": account, "state": email_state, "list": list, "notFound": not_found },
		call_id,
	])
}
