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
pub(crate) fn owner_of(state: &ApiState, principal: &Principal) -> Option<String> {
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

/// Every property a PushSubscription has (RFC 8620 §7.2).
const PROPERTIES: [&str; 7] = [
	"id",
	"deviceClientId",
	"url",
	"keys",
	"verificationCode",
	"expires",
	"types",
];

/// The properties `get` never returns: where and how a push reaches one
/// device is private to that device (RFC 8620 §7.2.1).
const PRIVATE: [&str; 2] = ["url", "keys"];

/// The properties a `get` returns, from its `properties` argument: null or
/// omitted is every property but [`PRIVATE`], and `id` is always returned
/// (RFC 8620 §5.1). Asking for a private one is `forbidden`, an unknown one
/// `invalidArguments`.
fn wanted_properties(args: &Value, call_id: &str) -> Result<Vec<&'static str>, Value> {
	let names = match args.get("properties") {
		None | Some(Value::Null) => {
			return Ok(PROPERTIES
				.into_iter()
				.filter(|p| !PRIVATE.contains(p))
				.collect());
		}
		Some(Value::Array(names)) => names,
		Some(_) => return Err(json!(["error", { "type": "invalidArguments" }, call_id])),
	};
	let mut wanted = vec!["id"];
	for name in names {
		let Some(property) = PROPERTIES.into_iter().find(|p| Some(*p) == name.as_str()) else {
			return Err(json!(["error", { "type": "invalidArguments" }, call_id]));
		};
		if PRIVATE.contains(&property) {
			return Err(forbidden(call_id));
		}
		if !wanted.contains(&property) {
			wanted.push(property);
		}
	}
	Ok(wanted)
}

/// `stored` reduced to `properties`, an unset one reported as null.
fn project(stored: &Value, properties: &[&str]) -> Value {
	let object: serde_json::Map<String, Value> = properties
		.iter()
		.map(|p| {
			(
				p.to_string(),
				stored.get(*p).cloned().unwrap_or(Value::Null),
			)
		})
		.collect();
	Value::Object(object)
}

/// `PushSubscription/get` (RFC 8620 §7.2.1): the caller's own subscriptions,
/// optionally narrowed by `ids`. An id the caller does not own is reported in
/// `notFound`, the same as one that does not exist. `url` and `keys` are never
/// returned, and the response carries no `state`.
pub(crate) fn get(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	let Some(owner) = owner_of(state, principal) else {
		return forbidden(call_id);
	};
	let properties = match wanted_properties(args, call_id) {
		Ok(properties) => properties,
		Err(error) => return error,
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
		None => own
			.iter()
			.map(|sub| project(&sub.object, &properties))
			.collect(),
		Some(ids) => ids
			.iter()
			.filter_map(Value::as_str)
			.filter_map(|id| {
				let found = own.iter().find(|sub| sub.id() == Some(id));
				if found.is_none() {
					not_found.push(json!(id));
				}
				found.map(|sub| project(&sub.object, &properties))
			})
			.collect(),
	};
	json!(["PushSubscription/get", { "list": list, "notFound": not_found }, call_id])
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
			if let Err(error) = check_create(props) {
				not_created.insert(key.clone(), error);
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
			let patch = match check_update(patch) {
				Ok(patch) => patch,
				Err(error) => {
					not_updated.insert(id.clone(), error);
					continue;
				}
			};
			if let Some(target) = sub.object.as_object_mut() {
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

/// The properties an update may change (RFC 8620 §7.2): `url`, `keys` and
/// `deviceClientId` are immutable and `id` is server-set, so a patch touching
/// them is refused. Without this an update could swap the checked `url` for an
/// unchecked one.
const UPDATABLE: [&str; 3] = ["verificationCode", "expires", "types"];

fn invalid(properties: &[&str]) -> Value {
	json!({ "type": "invalidProperties", "properties": properties })
}

/// Check a create: the delivery `url` must be an absolute `https` URL with a
/// host and no embedded credentials, the same rule every outbound request
/// that carries a secret follows ([`crate::net::HttpsUrl`]); nothing is
/// pushed yet, but a stored subscription must already be one we could
/// deliver to safely. `expires`, when present, must be a UTCDate.
fn check_create(props: &Value) -> Result<(), Value> {
	let url_ok = props
		.get("url")
		.and_then(Value::as_str)
		.is_some_and(|url| crate::net::HttpsUrl::parse(url).is_ok());
	let mut bad = Vec::new();
	if !url_ok {
		bad.push("url");
	}
	if !expires_ok(props.get("expires")) {
		bad.push("expires");
	}
	if bad.is_empty() {
		Ok(())
	} else {
		Err(invalid(&bad))
	}
}

/// Check an update patch: only [`UPDATABLE`] properties, and a valid
/// `expires`. Returns the patch's properties to apply.
fn check_update(patch: &Value) -> Result<&serde_json::Map<String, Value>, Value> {
	let Some(patch) = patch.as_object() else {
		return Err(json!({ "type": "invalidPatch" }));
	};
	let mut bad: Vec<&str> = patch
		.keys()
		.map(String::as_str)
		.filter(|key| !UPDATABLE.contains(key))
		.collect();
	if !expires_ok(patch.get("expires")) {
		bad.push("expires");
	}
	if bad.is_empty() {
		Ok(patch)
	} else {
		Err(invalid(&bad))
	}
}

/// `expires` is `UTCDate|null` (RFC 8620 §7.2); absent is the same as null.
fn expires_ok(expires: Option<&Value>) -> bool {
	match expires {
		None | Some(Value::Null) => true,
		Some(Value::String(text)) => is_utc_date(text),
		Some(_) => false,
	}
}

/// Whether `text` is a UTCDate (RFC 8620 §1.4): `YYYY-MM-DDThh:mm:ss`, an
/// optional fraction of a second, and `Z`, naming a day the month has.
fn is_utc_date(text: &str) -> bool {
	let Some(body) = text.strip_suffix('Z') else {
		return false;
	};
	let (clock, fraction) = body.split_once('.').unwrap_or((body, "0"));
	let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
	let bytes = clock.as_bytes();
	if !digits(fraction) || bytes.len() != 19 || !clock.is_ascii() {
		return false;
	}
	if [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')]
		.iter()
		.any(|&(at, sep)| bytes[at] != sep)
	{
		return false;
	}
	let field = |at: usize, len: usize| {
		let part = &clock[at..at + len];
		if digits(part) {
			part.parse::<i64>().ok()
		} else {
			None
		}
	};
	let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
		field(0, 4),
		field(5, 2),
		field(8, 2),
		field(11, 2),
		field(14, 2),
		field(17, 2),
	) else {
		return false;
	};
	if !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return false;
	}
	// A day past the end of the month (`2030-02-30`) rolls into the next one
	// on the way through days-since-epoch, so the round trip catches it.
	let days = crate::webdav::rrule::days_from_civil(year, month, day);
	crate::webdav::rrule::civil_from_secs(days * 86_400) == (year, month, day)
}
