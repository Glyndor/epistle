//! The per-object half of `SieveScript/set` (RFC 9661 section 2.4): what one
//! `create` and one `update` entry mean, and the SetError each refusal is.
//!
//! Every change is made through the [`Tx`] the whole call runs in, under the
//! account's lock; here only the shape of the request is checked, and the
//! blob a script's content comes from is read from what the request
//! uploaded.

use serde_json::{Map, Value, json};

use super::sieve_blob;
use super::sieve_content::set_error;
use super::uploads::Uploads;
use crate::managesieve::store::{ScriptInfo, StoreError, Tx, Validated, is_valid_name};

/// How many generated names are tried before giving up: a name is eight hex
/// digits, so a clash is rare, and so is a second one.
const NAME_ATTEMPTS: usize = 5;

/// What one `/set` call works on.
pub(super) struct Edit<'a> {
	pub(super) account: &'a str,
	/// Whether the credential has the `send` scope.
	pub(super) can_send: bool,
	pub(super) uploads: &'a Uploads,
}

fn invalid_properties(names: &[&str]) -> Value {
	json!({"type": "invalidProperties", "properties": names})
}

/// `object` as the server reports a script it created.
fn created_object(script: &ScriptInfo) -> Value {
	json!({
		"id": script.id,
		"name": script.name,
		"blobId": sieve_blob::blob_id(&script.id, script.rev),
		"isActive": script.active,
	})
}

/// The SetError for a script that sends mail, from a credential that may not.
fn needs_send() -> Value {
	json!({
		"type": "forbidden",
		"description": "a script that redirects, replies or rejects needs the send scope",
	})
}

impl Edit<'_> {
	/// `Err` when the script sends mail and the credential has no `send`
	/// scope: `write` stores a filter, and does not originate mail.
	fn allowed(&self, sends: bool) -> Result<(), Value> {
		if self.can_send || !sends {
			Ok(())
		} else {
			Err(needs_send())
		}
	}

	/// The `alreadyExists` SetError for `name`, with the id of the script
	/// that has it (RFC 9661 section 2.4).
	fn already_exists(tx: &Tx<'_>, name: &str) -> Value {
		let existing = tx.scripts().into_iter().find(|s| s.name == name);
		match existing {
			Some(script) => json!({"type": "alreadyExists", "existingId": script.id}),
			None => json!({"type": "alreadyExists"}),
		}
	}

	fn refusal(tx: &Tx<'_>, error: &StoreError, name: Option<&str>) -> Value {
		match (error, name) {
			(StoreError::AlreadyExists, Some(name)) => Self::already_exists(tx, name),
			_ => set_error(error),
		}
	}

	/// The script in the blob named by `value`, checked (once per blob for
	/// the whole request), and whether it sends mail.
	fn content(&self, value: &Value) -> Result<(Validated, bool), Value> {
		let Some(blob_id) = value.as_str() else {
			return Err(invalid_properties(&["blobId"]));
		};
		let verdict = self.uploads.script(self.account, blob_id);
		match &verdict.script {
			Ok(text) => Ok((text.clone(), verdict.sends)),
			Err(unusable) => Err(unusable.set_error_for(blob_id)),
		}
	}

	/// The object's `name`, when it has one: valid, or the SetError.
	fn name<'v>(&self, object: &'v Map<String, Value>) -> Result<Option<&'v str>, Value> {
		match object.get("name") {
			None => Ok(None),
			Some(Value::String(name)) if is_valid_name(name) => Ok(Some(name)),
			Some(_) => Err(invalid_properties(&["name"])),
		}
	}

	/// One `create` entry: a name (or none, and the server picks one) and
	/// the blob with the content. `id` and `isActive` are the server's.
	pub(super) fn create(&self, tx: &mut Tx<'_>, spec: &Value) -> Result<Value, Value> {
		let Some(object) = spec.as_object() else {
			return Err(json!({"type": "invalidProperties"}));
		};
		let unknown: Vec<&str> = object
			.keys()
			.map(String::as_str)
			.filter(|key| !matches!(*key, "name" | "blobId"))
			.collect();
		if !unknown.is_empty() {
			return Err(invalid_properties(&unknown));
		}
		let name = if object.get("name").is_some_and(Value::is_null) {
			None
		} else {
			self.name(object)?
		};
		let (text, sends) = self.content(object.get("blobId").unwrap_or(&Value::Null))?;
		self.allowed(sends)?;
		let created = match name {
			Some(name) => tx.create_validated(name, &text),
			None => Self::create_unnamed(tx, &text),
		};
		created
			.map(|script| created_object(&script))
			.map_err(|error| Self::refusal(tx, &error, name))
	}

	/// Create a script under a name of the server's choosing.
	fn create_unnamed(tx: &mut Tx<'_>, text: &Validated) -> Result<ScriptInfo, StoreError> {
		let mut last = StoreError::AlreadyExists;
		for _ in 0..NAME_ATTEMPTS {
			let unique = uuid::Uuid::now_v7().simple().to_string();
			match tx.create_validated(&format!("script-{}", &unique[24..]), text) {
				Err(StoreError::AlreadyExists) => last = StoreError::AlreadyExists,
				outcome => return outcome,
			}
		}
		Err(last)
	}

	/// One `update` entry: a new `name`, a new `blobId`, or both. What the
	/// server changed beyond the request is the result: a new content has a
	/// new blob id.
	pub(super) fn update(&self, tx: &mut Tx<'_>, id: &str, patch: &Value) -> Result<Value, Value> {
		let Some(object) = patch.as_object() else {
			return Err(json!({"type": "invalidPatch"}));
		};
		if object.keys().any(|key| key.contains('/')) {
			return Err(json!({"type": "invalidPatch"}));
		}
		let unknown: Vec<&str> = object
			.keys()
			.map(String::as_str)
			.filter(|key| !matches!(*key, "name" | "blobId"))
			.collect();
		if !unknown.is_empty() {
			return Err(invalid_properties(&unknown));
		}
		let name = self.name(object)?;
		// An id that names no script is refused before a blob is looked at.
		if !tx.scripts().iter().any(|script| script.id == id) {
			return Err(set_error(&StoreError::NoSuchScript));
		}
		let text = object
			.get("blobId")
			.map(|value| self.content(value))
			.transpose()?;
		if let Some((_, sends)) = &text {
			self.allowed(*sends)?;
		}
		let script = tx
			.update_validated(id, name, text.as_ref().map(|(text, _)| text))
			.map_err(|error| Self::refusal(tx, &error, name))?;
		Ok(match text {
			Some(_) => json!({"blobId": sieve_blob::blob_id(&script.id, script.rev)}),
			None => Value::Null,
		})
	}
}
