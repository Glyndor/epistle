//! What `EmailSubmission` says about the send delay (RFC 8621 section 7):
//! `sendAt` and `undoStatus` of a created submission, and the update that
//! cancels one.

use serde_json::{Map, Value, json};

use super::super::state::ApiState;
use crate::storage::undo::{CancelError, Canceller};

/// The server-set fields of a created submission `id`: `pending` with the
/// time it will be sent while the send delay holds it, `final` and no time
/// when it was handed on at once.
pub(super) fn created(state: &ApiState, account: &str, id: &str) -> Value {
	let release_at = uuid::Uuid::parse_str(id)
		.ok()
		.and_then(|id| state.held_until(account, id));
	match release_at {
		Some(at) => json!({
			"id": id,
			"sendAt": crate::clock::rfc3339(at),
			"undoStatus": "pending",
		}),
		None => json!({ "id": id, "sendAt": null, "undoStatus": "final" }),
	}
}

/// Apply the `update` of `EmailSubmission/set`: the only change allowed is
/// `undoStatus: "canceled"` (RFC 8621 section 7.5), for a submission of
/// `account`. Returns the `updated` and `notUpdated` maps.
pub(super) fn updates(
	state: &ApiState,
	account: &str,
	update: &Map<String, Value>,
) -> (Map<String, Value>, Map<String, Value>) {
	let mut updated = Map::new();
	let mut not_updated = Map::new();
	for (id, patch) in update {
		match cancel(state, account, id, patch) {
			Ok(()) => {
				updated.insert(id.clone(), Value::Null);
			}
			Err(error) => {
				not_updated.insert(id.clone(), error);
			}
		}
	}
	(updated, not_updated)
}

fn cancel(state: &ApiState, account: &str, id: &str, patch: &Value) -> Result<(), Value> {
	let only_cancel = patch.as_object().is_some_and(|fields| {
		fields.len() == 1 && fields.get("undoStatus").and_then(Value::as_str) == Some("canceled")
	});
	if !only_cancel {
		return Err(json!({
			"type": "invalidProperties",
			"properties": ["undoStatus"],
			"description": "the only change allowed is undoStatus: canceled",
		}));
	}
	let Ok(id) = uuid::Uuid::parse_str(id) else {
		return Err(json!({ "type": "notFound" }));
	};
	let store = state
		.undo_store()
		.map_err(|_| json!({ "type": "serverFail" }))?;
	match store.cancel_now(id, Canceller::Account(account)) {
		Ok(()) => Ok(()),
		Err(CancelError::AlreadySent) => Err(json!({
			"type": "cannotUnsend",
			"description": "the message was already handed on and cannot be cancelled",
		})),
		Err(CancelError::NotFound) => Err(json!({ "type": "notFound" })),
		Err(CancelError::Io(_)) => Err(json!({ "type": "serverFail" })),
	}
}
