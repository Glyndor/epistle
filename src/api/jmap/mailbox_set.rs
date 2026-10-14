//! `Mailbox/set` (RFC 8621 §2.5): create, rename, move and destroy
//! mailboxes.
//!
//! A mailbox id is its stored name (`Work/Project`). A create or update names
//! one level in UTF-8 (`name`) under a parent (`parentId`, an id, a `#cid`
//! creation reference, or `null` for the top level); the stored name is the
//! parent's id, `/`, and the level in modified UTF-7. Changing either renames
//! the mailbox, and its children move with it.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::state;
use crate::imap::mailbox;
use crate::util::mailbox_path;

/// `Mailbox/set` for `args`.
pub(super) fn mailbox_set(
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
	let dir = state.data_dir();
	let target = Target { dir, account };
	let old_state = state::mailbox_get_state(dir, account).unwrap_or_else(|| "0".to_string());
	let (created, not_created) = target.create_all(args.get("create"));
	let (updated, not_updated) = target.update_all(args.get("update"), &created);
	let (destroyed, not_destroyed) = target.destroy_all(args.get("destroy"));
	let new_state = state::mailbox_get_state(dir, account).unwrap_or_else(|| "0".to_string());
	json!([
		"Mailbox/set",
		{ "accountId": account, "oldState": old_state, "newState": new_state,
		  "created": created, "notCreated": not_created,
		  "updated": updated, "notUpdated": not_updated,
		  "destroyed": destroyed, "notDestroyed": not_destroyed },
		call_id,
	])
}

fn set_error(kind: &str) -> Value {
	json!({ "type": kind })
}

/// How a `parentId` resolved.
enum Parent {
	/// The parent's id, or `None` for the top level.
	Resolved(Option<String>),
	/// A `#cid` reference to a creation not made yet in this call.
	Waiting,
	/// Not a mailbox, a failed creation, or not a string.
	Invalid,
}

struct Target<'a> {
	dir: &'a std::path::Path,
	account: &'a str,
}

impl Target<'_> {
	/// Resolve a `parentId` against the existing mailboxes and the creations
	/// made so far in this call. `pending` holds the creation ids not
	/// attempted yet.
	fn parent(
		&self,
		value: Option<&Value>,
		created: &Map<String, Value>,
		pending: &HashSet<&str>,
	) -> Parent {
		match value {
			None | Some(Value::Null) => Parent::Resolved(None),
			Some(Value::String(id)) => match id.strip_prefix('#') {
				Some(cid) => match created.get(cid).and_then(|made| made["id"].as_str()) {
					Some(made) => Parent::Resolved(Some(made.to_string())),
					None if pending.contains(cid) => Parent::Waiting,
					None => Parent::Invalid,
				},
				None if mailbox::exists(self.dir, self.account, id) => {
					Parent::Resolved(Some(id.clone()))
				}
				None => Parent::Invalid,
			},
			Some(_) => Parent::Invalid,
		}
	}

	/// Create every mailbox in `create`. A child may name its parent's
	/// creation (`#cid`) in any order, so creations run in rounds until a
	/// round makes no progress; what is left refers to nothing that exists.
	fn create_all(&self, create: Option<&Value>) -> (Map<String, Value>, Map<String, Value>) {
		let (mut created, mut not_created) = (Map::new(), Map::new());
		let Some(create) = create.and_then(Value::as_object) else {
			return (created, not_created);
		};
		let mut pending: Vec<&str> = create.keys().map(String::as_str).collect();
		loop {
			let before = pending.len();
			let mut next = Vec::with_capacity(pending.len());
			let waiting: HashSet<&str> = pending.iter().copied().collect();
			for &cid in &pending {
				let spec = &create[cid];
				let own = spec.get("parentId").and_then(Value::as_str) == Some(&format!("#{cid}"));
				let parent = match self.parent(spec.get("parentId"), &created, &waiting) {
					_ if own => Parent::Invalid,
					parent => parent,
				};
				let parent = match parent {
					Parent::Waiting => {
						next.push(cid);
						continue;
					}
					Parent::Invalid => None,
					Parent::Resolved(parent) => Some(parent),
				};
				let stored = parent.and_then(|parent| {
					let name = spec.get("name").and_then(Value::as_str)?;
					mailbox_path::child_of(parent.as_deref(), name)
				});
				match stored {
					Some(stored) if mailbox::create(self.dir, self.account, &stored).is_ok() => {
						created.insert(cid.to_string(), json!({ "id": stored }));
					}
					_ => {
						not_created.insert(cid.to_string(), set_error("invalidProperties"));
					}
				}
			}
			pending = next;
			if pending.is_empty() || pending.len() == before {
				break;
			}
		}
		for cid in pending {
			not_created.insert(cid.to_string(), set_error("invalidProperties"));
		}
		(created, not_created)
	}

	/// Apply every patch in `update`: `name` renames the last level,
	/// `parentId` moves the mailbox, and the mailbox's children follow.
	fn update_all(
		&self,
		update: Option<&Value>,
		created: &Map<String, Value>,
	) -> (Map<String, Value>, Map<String, Value>) {
		let (mut updated, mut not_updated) = (Map::new(), Map::new());
		let Some(update) = update.and_then(Value::as_object) else {
			return (updated, not_updated);
		};
		for (id, patch) in update {
			let exists = mailbox::exists(self.dir, self.account, id);
			match self.renamed(id, patch, created) {
				Some(target) if exists && target == *id => {
					updated.insert(id.clone(), Value::Null);
				}
				Some(target) if mailbox::rename(self.dir, self.account, id, &target).is_ok() => {
					updated.insert(id.clone(), Value::Null);
				}
				_ => {
					not_updated.insert(id.clone(), set_error("invalidProperties"));
				}
			}
		}
		(updated, not_updated)
	}

	/// The stored name `patch` gives the mailbox `id`, or `None` when the
	/// patch sets neither `name` nor `parentId`, or one of them to a value of
	/// the wrong type. Other properties are not stored and are ignored, as
	/// they were before.
	fn renamed(&self, id: &str, patch: &Value, created: &Map<String, Value>) -> Option<String> {
		let patch = patch.as_object()?;
		if !patch.contains_key("name") && !patch.contains_key("parentId") {
			return None;
		}
		let parent = match patch.get("parentId") {
			None => mailbox_path::parent(id).map(str::to_string),
			value => match self.parent(value, created, &HashSet::new()) {
				Parent::Resolved(parent) => parent,
				Parent::Waiting | Parent::Invalid => return None,
			},
		};
		let name = match patch.get("name") {
			None => mailbox_path::display_leaf(id),
			Some(value) => value.as_str()?.to_string(),
		};
		mailbox_path::child_of(parent.as_deref(), &name)
	}

	/// Destroy every listed mailbox; one with children is refused with
	/// `mailboxHasChild` (RFC 8621 §2.5).
	fn destroy_all(&self, destroy: Option<&Value>) -> (Vec<Value>, Map<String, Value>) {
		let (mut destroyed, mut not_destroyed) = (Vec::new(), Map::new());
		let Some(ids) = destroy.and_then(Value::as_array) else {
			return (destroyed, not_destroyed);
		};
		for id in ids.iter().filter_map(Value::as_str) {
			match mailbox::delete(self.dir, self.account, id) {
				Ok(()) => destroyed.push(Value::String(id.to_string())),
				Err(error) if error.to_string().starts_with("[HASCHILDREN]") => {
					not_destroyed.insert(id.to_string(), set_error("mailboxHasChild"));
				}
				Err(_) => {
					not_destroyed.insert(id.to_string(), set_error("notFound"));
				}
			}
		}
		(destroyed, not_destroyed)
	}
}
