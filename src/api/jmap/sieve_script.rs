//! `SieveScript/get` (RFC 9661 section 2.3): the account's Sieve scripts.
//!
//! The scripts are the ManageSieve store's, so a script written by either
//! protocol is listed here. An account reads only its own: the account is
//! admitted the way every other per-account method admits it, and the store
//! it opens is that account's.

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::sieve_blob;
use crate::managesieve::store::{ScriptInfo, StoreError};

/// The properties of a `SieveScript` (RFC 9661 section 2.1).
pub(super) const PROPERTIES: [&str; 4] = ["id", "name", "blobId", "isActive"];

pub(super) fn method_error(kind: &str, call_id: &str) -> Value {
	json!(["error", { "type": kind }, call_id])
}

/// The state string for the store's change counter.
pub(super) fn state_string(counter: u64) -> String {
	counter.to_string()
}

/// A failure of the script store, as a method error. The cause stays in the
/// log: it is a path or an OS message, not something a client can act on.
pub(super) fn store_failure(error: &StoreError, call_id: &str) -> Value {
	tracing::warn!(?error, "the Sieve script store failed a JMAP call");
	method_error("serverFail", call_id)
}

/// The `properties` argument: every property when absent or null, `None`
/// when it is not a list of known names.
pub(super) fn requested_properties(args: &Value) -> Option<Vec<&'static str>> {
	match args.get("properties") {
		None | Some(Value::Null) => Some(PROPERTIES.to_vec()),
		Some(Value::Array(names)) => names
			.iter()
			.map(|name| {
				let name = name.as_str()?;
				PROPERTIES.iter().copied().find(|known| *known == name)
			})
			.collect(),
		Some(_) => None,
	}
}

/// A script as a JMAP object, keeping `id` and the requested properties.
pub(super) fn object(script: &ScriptInfo, properties: &[&str]) -> Value {
	let mut object = json!({
		"id": script.id,
		"name": script.name,
		"blobId": sieve_blob::blob_id(&script.id, script.rev),
		"isActive": script.active,
	});
	if let Some(fields) = object.as_object_mut() {
		fields.retain(|name, _| name == "id" || properties.contains(&name.as_str()));
	}
	object
}

/// `SieveScript/get`.
pub(crate) fn get(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	let account = match super::state::admitted_account(state, principal, args, call_id) {
		Ok(account) => account,
		Err(error) => return error,
	};
	let Some(properties) = requested_properties(args) else {
		return method_error("invalidArguments", call_id);
	};
	let wanted: Option<Vec<&str>> = match args.get("ids") {
		None | Some(Value::Null) => None,
		Some(Value::Array(ids)) => match ids.iter().map(Value::as_str).collect::<Option<_>>() {
			Some(ids) => Some(ids),
			None => return method_error("invalidArguments", call_id),
		},
		Some(_) => return method_error("invalidArguments", call_id),
	};
	let (counter, scripts) = match sieve_blob::store(state.data_dir(), &account).snapshot() {
		Ok(snapshot) => snapshot,
		Err(error) => return store_failure(&error, call_id),
	};
	let (list, not_found) = match wanted {
		None => (
			scripts.iter().map(|s| object(s, &properties)).collect(),
			Vec::new(),
		),
		Some(ids) => {
			let mut list = Vec::new();
			let mut not_found = Vec::new();
			for id in ids {
				match scripts.iter().find(|script| script.id == id) {
					Some(script) => list.push(object(script, &properties)),
					None => not_found.push(id),
				}
			}
			(list, not_found)
		}
	};
	json!([
		"SieveScript/get",
		{
			"accountId": account,
			"state": state_string(counter),
			"list": list,
			"notFound": not_found,
		},
		call_id,
	])
}
