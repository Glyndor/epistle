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
use crate::managesieve::store::{ScriptStore, StoreError};

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
	let old_state = state_string(store.state().map_err(|e| store_failure(&e, call_id))?);
	if let Some(expected) = args.get("ifInState").filter(|value| !value.is_null())
		&& expected.as_str() != Some(old_state.as_str())
	{
		return Err(method_error("stateMismatch", call_id));
	}
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

	let edit = Edit {
		store: &store,
		account: &account,
		uploads,
	};
	let mut out = Outcome::default();
	for (cid, spec) in create.into_iter().flatten() {
		match edit.create(spec) {
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
	for (id, patch) in update.into_iter().flatten() {
		match edit.update(id, patch) {
			Ok(result) => {
				out.updated.insert(id.clone(), result);
			}
			Err(error) => {
				out.not_updated.insert(id.clone(), error);
			}
		}
	}
	for id in destroy {
		match store.destroy(id) {
			Ok(()) => out.destroyed.push(json!(id)),
			Err(error) => {
				out.not_destroyed.insert(id.to_string(), set_error(&error));
			}
		}
	}
	if out.all_succeeded() {
		switch_active(&store, activate, deactivate, &mut out)
			.map_err(|error| store_failure(&error, call_id))?;
	}
	let new_state = state_string(store.state().map_err(|e| store_failure(&e, call_id))?);
	Ok(json!([
		"SieveScript/set",
		{
			"accountId": account,
			"oldState": old_state,
			"newState": new_state,
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

/// `onSuccessDeactivateScript`, then `onSuccessActivateScript`. An id that
/// names no script is ignored and the active script stays as it is.
fn switch_active(
	store: &ScriptStore,
	activate: Option<&str>,
	deactivate: bool,
	out: &mut Outcome,
) -> Result<(), StoreError> {
	if activate.is_none() && !deactivate {
		return Ok(());
	}
	let scripts = store.list()?;
	let mut active = scripts.iter().find(|script| script.active);
	if deactivate && let Some(current) = active.take() {
		store.set_active(None)?;
		out.report_active(&current.id, false);
	}
	let target = activate.and_then(|id| match id.strip_prefix('#') {
		Some(cid) => out.creation_ids.get(cid).cloned(),
		None => Some(id.to_string()),
	});
	let Some(target) = target.and_then(|id| scripts.iter().find(|script| script.id == id)) else {
		return Ok(());
	};
	if active.is_some_and(|current| current.id == target.id) {
		return Ok(());
	}
	match store.set_active(Some(&target.name)) {
		Ok(()) => {}
		// Renamed or deleted since it was listed: it is no script, so ignored.
		Err(StoreError::NoSuchScript) => return Ok(()),
		Err(error) => return Err(error),
	}
	if let Some(previous) = active {
		out.report_active(&previous.id, false);
	}
	out.report_active(&target.id, true);
	Ok(())
}
