//! `Mailbox/queryChanges` and `Email/queryChanges` (RFC 8620 section 5.6).
//!
//! Supported queries are the ones whose results the journal can replay
//! exactly:
//! - `Mailbox/query` ignores filter and sort (its results are INBOX then the
//!   folders by name), so every Mailbox query is supported.
//! - `Email/query` with no filter or a filter of only `inMailbox`, sorted by
//!   the default newest first (no sort, an empty sort, or `receivedAt`
//!   descending).
//!
//! Any other Email query answers `cannotCalculateChanges`, and its
//! `Email/query` reply says `canCalculateChanges: false`.

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::fold::{Folded, Outcome, fold};
use super::state::{Kind, State, admitted_account, entries_since, max_changes};
use crate::imap::changelog::Object;

/// The mailbox an Email query lists, or `None` when the journal cannot
/// replay the query's results.
pub(super) fn replayable_email_query(args: &Value) -> Option<String> {
	let mailbox = match args.get("filter") {
		None | Some(Value::Null) => "INBOX".to_string(),
		Some(Value::Object(filter)) if filter.is_empty() => "INBOX".to_string(),
		Some(Value::Object(filter)) if filter.len() == 1 => {
			filter.get("inMailbox")?.as_str()?.to_string()
		}
		Some(_) => return None,
	};
	let newest_first = |comparator: &Value| {
		comparator.get("property").and_then(Value::as_str) == Some("receivedAt")
			&& comparator.get("isAscending").and_then(Value::as_bool) == Some(false)
	};
	match args.get("sort") {
		None | Some(Value::Null) => Some(mailbox),
		Some(Value::Array(sort)) if sort.is_empty() => Some(mailbox),
		Some(Value::Array(sort)) if sort.len() == 1 && newest_first(&sort[0]) => Some(mailbox),
		Some(_) => None,
	}
}

/// The ids `Email/query` returns for `mailbox`: newest first.
pub(super) fn email_query_ids(state: &ApiState, account: &str, mailbox: &str) -> Vec<String> {
	let mut ids: Vec<String> =
		crate::imap::mailbox::Snapshot::open(state.data_dir(), account, mailbox, state.crypto())
			.map(|snapshot| snapshot.messages().map(|m| m.id().to_string()).collect())
			.unwrap_or_default();
	ids.reverse();
	ids
}

pub(super) fn email(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	reply(state, principal, args, call_id, Kind::Email)
}

pub(super) fn mailbox(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
) -> Value {
	reply(state, principal, args, call_id, Kind::Mailbox)
}

fn reply(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	kind: Kind,
) -> Value {
	match query_changes(state, principal, args, call_id, kind) {
		Ok(reply) | Err(reply) => reply,
	}
}

fn query_changes(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	kind: Kind,
) -> Result<Value, Value> {
	let account = admitted_account(state, principal, args, call_id)?;
	let max = max_changes(args, call_id)?;
	let since_value = args
		.get("sinceQueryState")
		.and_then(Value::as_str)
		.unwrap_or("");
	let (method, object, current) = if kind == Kind::Email {
		let mailbox = replayable_email_query(args)
			.ok_or_else(|| json!(["error", { "type": "cannotCalculateChanges" }, call_id]))?;
		let ids = email_query_ids(state, &account, &mailbox);
		("Email/queryChanges", Object::Email, ids)
	} else {
		let ids = crate::imap::mailbox::list(state.data_dir(), &account);
		("Mailbox/queryChanges", Object::Mailbox, ids)
	};
	let (since, position, entries) = entries_since(state, &account, since_value, kind, call_id)?;
	let folded = fold(&entries, object, None, false, position.current);
	let (removed, added) = diff(&folded, &current, kind);
	if max.is_some_and(|max| removed.len() + added.len() > max) {
		return Err(json!(["error", { "type": "tooManyChanges" }, call_id]));
	}
	let new_state = State {
		position: position.current,
		..since
	};
	let mut reply = json!({
		"accountId": account,
		"oldQueryState": since_value,
		"newQueryState": new_state.encode(),
		"removed": removed,
		"added": added,
	});
	if args.get("calculateTotal").and_then(Value::as_bool) == Some(true) {
		reply["total"] = json!(current.len());
	}
	Ok(json!([method, reply, call_id]))
}

/// `removed` holds every changed id that existed at the old state (it may
/// have left the results, or moved within them); `added` holds every changed
/// id in the current results, with its index, lowest index first. A mailbox
/// whose counts alone changed keeps its place, so it is left out.
fn diff(folded: &Folded, current: &[String], kind: Kind) -> (Vec<String>, Vec<Value>) {
	let index_of: std::collections::HashMap<&str, usize> = current
		.iter()
		.enumerate()
		.map(|(index, id)| (id.as_str(), index))
		.collect();
	let mut removed = Vec::new();
	let mut added: Vec<(usize, String)> = Vec::new();
	for (id, outcome) in &folded.outcomes {
		let existed = match outcome {
			Outcome::Updated { only_updates: true } if kind == Kind::Mailbox => continue,
			Outcome::Created => false,
			Outcome::Updated { .. } | Outcome::Destroyed => true,
		};
		if existed {
			removed.push(id.clone());
		}
		if let Some(index) = index_of.get(id.as_str()) {
			added.push((*index, id.clone()));
		}
	}
	added.sort();
	let added = added
		.into_iter()
		.map(|(index, id)| json!({ "id": id, "index": index }))
		.collect();
	(removed, added)
}
