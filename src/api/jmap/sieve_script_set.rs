//! `SieveScript/set` (RFC 9661 section 2.4): create, rename, replace the
//! content of, activate, deactivate and destroy scripts.
//!
//! Exactly one script is active. Activation is the request's last step, taken
//! only when every create, update and destroy succeeded, and it
//! deactivates the script that was active, so there is never a moment with
//! two. The active script cannot be destroyed (`sieveIsActive`): it is
//! deactivated first, in a call of its own.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::sieve_blob;
use super::sieve_content::set_error;
use super::sieve_script::{method_error, state_string, store_failure};
use super::sieve_script_edit::Edit;
use super::uploads::Uploads;
use crate::api::api_keys::Scope;
use crate::managesieve::store::{StoreError, Tx};

/// The parts of the response, as they are filled in.
#[derive(Default)]
struct Outcome {
	created: Map<String, Value>,
	not_created: Map<String, Value>,
	updated: Map<String, Value>,
	not_updated: Map<String, Value>,
	destroyed: Vec<Value>,
	not_destroyed: Map<String, Value>,
	/// The id of each script this call created, by creation id.
	creation_ids: HashMap<String, String>,
}

impl Outcome {
	/// The id a request names: `#cid` is the script this call created under
	/// that creation id, anything else is an id as it stands.
	fn resolve(&self, key: &str) -> String {
		match key.strip_prefix('#') {
			Some(cid) => self
				.creation_ids
				.get(cid)
				.cloned()
				.unwrap_or_else(|| key.to_string()),
			None => key.to_string(),
		}
	}

	fn all_succeeded(&self) -> bool {
		self.not_created.is_empty() && self.not_updated.is_empty() && self.not_destroyed.is_empty()
	}

	/// Report that the script `id` is now active (or not): in `created`
	/// when this call created it, else in `updated`.
	fn report_active(&mut self, id: &str, active: bool) {
		let created = self
			.creation_ids
			.iter()
			.find(|(_, made)| made.as_str() == id)
			.map(|(cid, _)| cid.clone());
		if let Some(object) = created
			.and_then(|cid| self.created.get_mut(&cid))
			.and_then(Value::as_object_mut)
		{
			object.insert("isActive".into(), json!(active));
			return;
		}
		match self.updated.get_mut(id).and_then(Value::as_object_mut) {
			Some(object) => {
				object.insert("isActive".into(), json!(active));
			}
			None => {
				self.updated
					.insert(id.to_string(), json!({"isActive": active}));
			}
		}
	}
}

/// An optional argument that is an object.
fn object_argument<'a>(
	args: &'a Value,
	key: &str,
	call_id: &str,
) -> Result<Option<&'a Map<String, Value>>, Value> {
	match args.get(key) {
		None | Some(Value::Null) => Ok(None),
		Some(Value::Object(object)) => Ok(Some(object)),
		Some(_) => Err(method_error("invalidArguments", call_id)),
	}
}

/// `SieveScript/set`.
pub(crate) fn set(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	uploads: &Uploads,
) -> Value {
	match run(state, principal, args, call_id, uploads) {
		Ok(response) | Err(response) => response,
	}
}

fn run(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	uploads: &Uploads,
) -> Result<Value, Value> {
	let account = super::state::admitted_account(state, principal, args, call_id)?;
	let store = sieve_blob::store(state.data_dir(), &account);
	// The state the caller expects, as the counter it names. A string that
	// is no state this server minted is a state that is not the current one.
	let expected = match args.get("ifInState") {
		None | Some(Value::Null) => None,
		Some(Value::String(text)) => Some(
			text.parse::<u64>()
				.map_err(|_| method_error("stateMismatch", call_id))?,
		),
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};
	let create = object_argument(args, "create", call_id)?;
	let update = object_argument(args, "update", call_id)?;
	let destroy: Vec<&str> = match args.get("destroy") {
		None | Some(Value::Null) => Vec::new(),
		Some(Value::Array(ids)) => ids
			.iter()
			.map(Value::as_str)
			.collect::<Option<_>>()
			.ok_or_else(|| method_error("invalidArguments", call_id))?,
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};
	let activate = match args.get("onSuccessActivateScript") {
		None | Some(Value::Null) => None,
		Some(Value::String(id)) => Some(id.as_str()),
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};
	let deactivate = match args.get("onSuccessDeactivateScript") {
		None | Some(Value::Null) => false,
		Some(Value::Bool(flag)) => *flag,
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};

	let can_send = state
		.require_scope_for_principal(principal, Scope::Send)
		.is_ok();
	let edit = Edit {
		account: &account,
		can_send,
		uploads,
	};
	// The whole call is one step under the account's lock: the state it
	// expects is checked where it changes things, and nothing, not another
	// protocol and not another call, moves between its parts.
	let done = store.transact(expected, |tx| {
		let old_state = tx.state();
		// Activating a script that already sends mail takes the `send` scope
		// too, and is refused before the call changes anything.
		if !can_send
			&& let Some(id) = activate.filter(|id| !id.starts_with('#'))
			&& let Some(script) = tx.scripts().into_iter().find(|script| script.id == id)
			&& tx
				.content(&script.name)
				.is_ok_and(|text| crate::sieve::analysis::sends_mail(&text))
		{
			return Err(());
		}
		let mut out = Outcome::default();
		for (cid, spec) in create.into_iter().flatten() {
			match edit.create(tx, spec) {
				Ok(object) => {
					if let Some(id) = object["id"].as_str() {
						out.creation_ids.insert(cid.clone(), id.to_string());
					}
					out.created.insert(cid.clone(), object);
				}
				Err(error) => {
					out.not_created.insert(cid.clone(), error);
				}
			}
		}
		for (key, patch) in update.into_iter().flatten() {
			let id = out.resolve(key);
			match edit.update(tx, &id, patch) {
				Ok(result) => {
					out.updated.insert(id, result);
				}
				Err(error) => {
					out.not_updated.insert(key.clone(), error);
				}
			}
		}
		for key in destroy {
			let id = out.resolve(key);
			match tx.destroy(&id) {
				Ok(()) => out.destroyed.push(json!(id)),
				Err(error) => {
					out.not_destroyed.insert(key.to_string(), set_error(&error));
				}
			}
		}
		let activated = if out.all_succeeded() {
			switch_active(tx, activate, deactivate, &mut out)
		} else {
			Ok(())
		};
		Ok((old_state, tx.state(), out, activated))
	});
	let (old_state, new_state, out, activated) = match done {
		Ok(Ok(done)) => done,
		Ok(Err(())) => return Err(method_error("forbidden", call_id)),
		Err(StoreError::StateMismatch) => return Err(method_error("stateMismatch", call_id)),
		Err(error) => return Err(store_failure(&error, call_id)),
	};
	activated.map_err(|error| store_failure(&error, call_id))?;
	Ok(json!([
		"SieveScript/set",
		{
			"accountId": account,
			"oldState": state_string(old_state),
			"newState": state_string(new_state),
			"created": out.created,
			"notCreated": out.not_created,
			"updated": out.updated,
			"notUpdated": out.not_updated,
			"destroyed": out.destroyed,
			"notDestroyed": out.not_destroyed,
		},
		call_id,
	]))
}

/// `onSuccessDeactivateScript`, then `onSuccessActivateScript`, as one change:
/// the script that ends up active is the one named, else none when asked to
/// deactivate, else the one that was. An id that names no script is ignored.
/// The change is made once, so delivery never sees a moment with no filter
/// between the one script and the other.
fn switch_active(
	tx: &mut Tx<'_>,
	activate: Option<&str>,
	deactivate: bool,
	out: &mut Outcome,
) -> Result<(), StoreError> {
	if activate.is_none() && !deactivate {
		return Ok(());
	}
	let scripts = tx.scripts();
	let current = scripts.iter().find(|script| script.active);
	let target = activate
		.map(|id| out.resolve(id))
		.and_then(|id| scripts.iter().find(|script| script.id == id));
	let after = match (target, deactivate) {
		(Some(target), _) => Some(target),
		(None, true) => None,
		(None, false) => current,
	};
	if after.map(|script| &script.id) == current.map(|script| &script.id) {
		return Ok(());
	}
	tx.set_active(after.map(|script| script.id.as_str()))?;
	if let Some(previous) = current {
		out.report_active(&previous.id, false);
	}
	if let Some(now) = after {
		out.report_active(&now.id, true);
	}
	Ok(())
}
