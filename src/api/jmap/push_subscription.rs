//! PushSubscription objects (RFC 8620 §7.2).
//!
//! The methods are session-scoped: they take no `accountId`, so the account
//! gate every other JMAP method applies never runs on them. Instead each
//! subscription is stored with the caller that created it, and `get`/`set`
//! only ever see the caller's own (RFC 8620 §7.2.1: a server "MUST only return
//! push subscriptions that were created using authentication credentials for
//! the same user as the current request"). A subscription's `url` and `keys`
//! are where and how a push would be delivered, so another caller listing or
//! destroying them would be both a leak and a way to silence someone's device.
//!
//! The objects round-trip through `get`/`set` only: nothing is delivered to the
//! `url` (out-of-band push is out of scope, see [`super::websocket`]).

use serde_json::{Value, json};

use super::Principal;
use crate::api::api_keys::Scope;
use crate::api::state::ApiState;

/// The most subscriptions one caller may hold. A device registers one, so this
/// leaves room for a handful of devices per credential while keeping a single
/// credential from growing the in-memory store without bound.
pub(crate) const MAX_PER_CALLER: usize = 16;

/// One stored subscription and the caller that created it.
#[derive(Clone)]
pub(crate) struct StoredSubscription {
	/// The caller identity from [`owner_of`].
	owner: String,
	/// The subscription object as returned by `PushSubscription/get`.
	object: Value,
}

impl StoredSubscription {
	fn id(&self) -> Option<&str> {
		self.object.get("id").and_then(Value::as_str)
	}

	fn is(&self, owner: &str, id: &str) -> bool {
		self.owner == owner && self.id() == Some(id)
	}
}

/// The stable identity of the caller behind `principal`, the key subscriptions
/// are stored under. A credential bound to one account is that account, so
/// every key bound to it shares the account's subscriptions. Any other key is
/// its label, which survives a rotation of the secret, and the configured
/// static token is its own caller. `None` when the credential no longer maps
/// to a key, which owns nothing.
fn owner_of(state: &ApiState, principal: &Principal) -> Option<String> {
	if let Principal::Account { name, .. } = principal {
		return Some(format!("account:{name}"));
	}
	let Some(credential) = principal.credential() else {
		return matches!(principal, Principal::Admin { .. }).then(|| "token".to_string());
	};
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	const EVERY_SCOPE: &[Scope] = &[Scope::Read, Scope::Write, Scope::Send];
	state
		.api_keys()
		.snapshot()
		.iter()
		.find(|key| key.admits_any(&credential.token, credential.client_ip, now, EVERY_SCOPE))
		.map(|key| format!("key:{}", key.label))
}

fn forbidden(call_id: &str) -> Value {
	json!(["error", { "type": "forbidden" }, call_id])
}

/// `PushSubscription/get` (RFC 8620 §7.2.1): the caller's own subscriptions,
/// optionally narrowed by `ids`. An id the caller does not own is reported in
/// `notFound`, the same as one that does not exist.
pub(crate) fn get(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	let Some(owner) = owner_of(state, principal) else {
		return forbidden(call_id);
	};
	let own: Vec<StoredSubscription> = state.with_push_subscriptions(|store| {
		store
			.iter()
			.filter(|sub| sub.owner == owner)
			.cloned()
			.collect()
	});
	let mut not_found = Vec::new();
	let list: Vec<Value> = match args.get("ids").and_then(Value::as_array) {
		None => own.into_iter().map(|sub| sub.object).collect(),
		Some(ids) => ids
			.iter()
			.filter_map(Value::as_str)
			.filter_map(|id| {
				let found = own.iter().find(|sub| sub.id() == Some(id));
				if found.is_none() {
					not_found.push(json!(id));
				}
				found.map(|sub| sub.object.clone())
			})
			.collect(),
	};
	json!(["PushSubscription/get", { "state": "0", "list": list, "notFound": not_found }, call_id])
}

/// `PushSubscription/set` (RFC 8620 §7.2.2): create subscriptions under the
/// caller, and update or destroy only the caller's own. Another caller's id is
/// answered with `notFound`, so its existence is not revealed. Subscriptions
/// are validated and echoed but nothing is delivered, so server-set fields are
/// minimal: an id, and no `verificationCode` is sent.
pub(crate) fn set(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	let Some(owner) = owner_of(state, principal) else {
		return forbidden(call_id);
	};
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	let mut updated = serde_json::Map::new();
	let mut not_updated = serde_json::Map::new();
	let mut destroyed = Vec::new();
	let mut not_destroyed = serde_json::Map::new();

	let creates = args.get("create").and_then(Value::as_object);
	let updates = args.get("update").and_then(Value::as_object);
	let destroys = args.get("destroy").and_then(Value::as_array);
	state.with_push_subscriptions(|store| {
		for (key, props) in creates.into_iter().flatten() {
			// A subscription must carry a delivery `url` (RFC 8620 §7.2).
			if props
				.get("url")
				.and_then(Value::as_str)
				.is_none_or(str::is_empty)
			{
				not_created.insert(
					key.clone(),
					json!({ "type": "invalidProperties", "properties": ["url"] }),
				);
				continue;
			}
			if store.iter().filter(|sub| sub.owner == owner).count() >= MAX_PER_CALLER {
				not_created.insert(
					key.clone(),
					json!({
						"type": "overQuota",
						"description": format!("at most {MAX_PER_CALLER} push subscriptions"),
					}),
				);
				continue;
			}
			let id = uuid::Uuid::now_v7().to_string();
			let mut object = props.clone();
			if let Some(map) = object.as_object_mut() {
				map.insert("id".to_string(), json!(id));
				// We never verify or push, so report no pending keys.
				map.entry("verificationCode").or_insert(Value::Null);
			}
			store.push(StoredSubscription {
				owner: owner.clone(),
				object,
			});
			created.insert(key.clone(), json!({ "id": id }));
		}
		for (id, patch) in updates.into_iter().flatten() {
			let Some(sub) = store.iter_mut().find(|sub| sub.is(&owner, id)) else {
				not_updated.insert(id.clone(), json!({ "type": "notFound" }));
				continue;
			};
			if let (Some(target), Some(patch)) = (sub.object.as_object_mut(), patch.as_object()) {
				for (k, v) in patch {
					target.insert(k.clone(), v.clone());
				}
			}
			updated.insert(id.clone(), Value::Null);
		}
		for id in destroys.into_iter().flatten().filter_map(Value::as_str) {
			match store.iter().position(|sub| sub.is(&owner, id)) {
				Some(index) => {
					store.remove(index);
					destroyed.push(json!(id));
				}
				None => {
					not_destroyed.insert(id.to_string(), json!({ "type": "notFound" }));
				}
			}
		}
	});

	json!([
		"PushSubscription/set",
		{
			"oldState": null, "newState": "0",
			"created": created, "notCreated": not_created,
			"updated": updated, "notUpdated": not_updated,
			"destroyed": destroyed, "notDestroyed": not_destroyed,
		},
		call_id
	])
}
