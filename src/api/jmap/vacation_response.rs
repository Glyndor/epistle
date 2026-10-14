//! `VacationResponse` JMAP object (RFC 8621 §8): the account's vacation
//! autoresponse setting. Stored at `<account>/.vacation.json`; `/get` reads
//! it, `/set` validates and rewrites it.
//!
//! The object is a singleton: only the id `singleton` is valid (RFC 8621
//! §8.2: "There MUST be exactly one VacationResponse object ... the id is
//! `singleton`"). `/set` therefore refuses `create` and `destroy` with
//! `forbidden` and only honours an `update` keyed by `singleton`. The
//! file's modification time is the `state` string, so any change is visible
//! to the next `/get`.

use serde_json::{Value, json};

use super::Principal;
use crate::api::state::ApiState;
use crate::storage::vacation_store::{
	self, MAX_BODY_BYTES, VacationSetting, read as read_setting, write as write_setting,
};
use crate::util::header::MAX_HEADER_VALUE_LEN;

/// The only id a `VacationResponse` ever has (RFC 8621 §8).
pub(crate) const SINGLETON_ID: &str = "singleton";

/// The full list of properties the JMAP object carries (RFC 8621 §8.1).
const PROPERTIES: [&str; 7] = [
	"id",
	"isEnabled",
	"fromDate",
	"toDate",
	"subject",
	"textBody",
	"htmlBody",
];

/// `VacationResponse/get` (RFC 8621 §8.2): read the singleton, returning the
/// stored fields. `accountId` is required, and a request naming an account
/// the principal does not have access to is refused with `accountNotFound`,
/// the same pattern every other per-account JMAP method uses. `ids` (null
/// for every object) and `properties` behave as for any `/get` (RFC 8620
/// section 5.1); `id` is always returned.
pub(crate) fn get(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	let account = match super::state::admitted_account(state, principal, args, call_id) {
		Ok(account) => account,
		Err(error) => return error,
	};
	let Some(properties) = requested_properties(args) else {
		return method_error("invalidArguments", call_id);
	};
	let (wanted, not_found): (Vec<&str>, Vec<&str>) = match args.get("ids") {
		None | Some(Value::Null) => (vec![SINGLETON_ID], Vec::new()),
		Some(Value::Array(ids)) => {
			match ids.iter().map(Value::as_str).collect::<Option<Vec<_>>>() {
				Some(ids) => ids.into_iter().partition(|id| *id == SINGLETON_ID),
				None => return method_error("invalidArguments", call_id),
			}
		}
		Some(_) => return method_error("invalidArguments", call_id),
	};
	let setting = read_setting(state.data_dir(), &account).unwrap_or_else(|error| {
		tracing::warn!(error = %error, account = %account, "vacation setting unreadable");
		VacationSetting::disabled()
	});
	let list: Vec<Value> = if wanted.is_empty() {
		Vec::new()
	} else {
		vec![project(&setting, &properties)]
	};
	json!([
		"VacationResponse/get",
		{
			"accountId": account,
			"state": state_string(state.data_dir(), &account),
			"list": list,
			"notFound": not_found,
		},
		call_id,
	])
}

/// `VacationResponse/set` (RFC 8621 §8.2): update the singleton. `create`
/// and `destroy` are refused with `forbidden`; an update of `singleton` is
/// validated and persisted. Validation: dates are UTCDate, `fromDate` is
/// not after `toDate`, both bodies stay under [`MAX_BODY_BYTES`], and the
/// subject fits one header line with no control characters. The
/// reverse-path the server emits, and its `Auto-Submitted: auto-replied`
/// marker, are server concerns, not user input. The `Write` scope is
/// checked by the dispatcher before this runs.
pub(crate) fn set(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	let account = match super::state::admitted_account(state, principal, args, call_id) {
		Ok(account) => account,
		Err(error) => return error,
	};
	let old_state = state_string(state.data_dir(), &account);
	if let Some(expected) = args.get("ifInState").filter(|value| !value.is_null())
		&& expected.as_str() != Some(old_state.as_str())
	{
		return method_error("stateMismatch", call_id);
	}
	let mut not_created = serde_json::Map::new();
	let mut not_updated = serde_json::Map::new();
	let mut not_destroyed = serde_json::Map::new();
	if let Some(creates) = args.get("create").and_then(Value::as_object) {
		for key in creates.keys() {
			not_created.insert(key.clone(), forbidden_value());
		}
	}
	if let Some(destroys) = args.get("destroy").and_then(Value::as_array) {
		for id in destroys.iter().filter_map(Value::as_str) {
			not_destroyed.insert(id.to_string(), forbidden_value());
		}
	}
	let mut updated = serde_json::Map::new();
	if let Some(updates) = args.get("update").and_then(Value::as_object) {
		for (id, patch) in updates {
			if id != SINGLETON_ID {
				not_updated.insert(id.clone(), json!({ "type": "notFound" }));
				continue;
			}
			let current = read_setting(state.data_dir(), &account)
				.unwrap_or_else(|_| VacationSetting::disabled());
			match apply_patch(&current, patch) {
				Ok(next) => {
					if let Err(error) = write_setting(state.data_dir(), &account, &next) {
						not_updated.insert(
							id.clone(),
							json!({ "type": "serverFail", "description": error.to_string() }),
						);
						continue;
					}
					updated.insert(id.clone(), Value::Null);
				}
				Err(error) => {
					not_updated.insert(id.clone(), error);
				}
			}
		}
	}
	let new_state = state_string(state.data_dir(), &account);
	json!([
		"VacationResponse/set",
		{
			"accountId": account,
			"oldState": old_state,
			"newState": new_state,
			"created": serde_json::Map::<String, Value>::new(),
			"notCreated": not_created,
			"updated": updated,
			"notUpdated": not_updated,
			"destroyed": Vec::<Value>::new(),
			"notDestroyed": not_destroyed,
		},
		call_id,
	])
}

/// The `properties` argument: every property when absent or null, `None`
/// when it is not a list of known names.
fn requested_properties(args: &Value) -> Option<Vec<&'static str>> {
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

/// Map a stored [`VacationSetting`] to its JMAP object form, keeping `id`
/// and the requested `properties`. Absent properties (e.g. `textBody` left
/// unset) become `null`, the same as the RFC's example shape.
fn project(setting: &VacationSetting, properties: &[&str]) -> Value {
	let mut object = json!({
		"id": SINGLETON_ID,
		"isEnabled": setting.is_enabled,
		"fromDate": setting.from_date,
		"toDate": setting.to_date,
		"subject": setting.subject,
		"textBody": setting.text_body,
		"htmlBody": setting.html_body,
	});
	if let Some(fields) = object.as_object_mut() {
		fields.retain(|name, _| name == "id" || properties.contains(&name.as_str()));
	}
	object
}

/// `state` for an account's singleton: the file's modification time in
/// nanoseconds since the epoch, `"0"` when the file does not exist. Every
/// write renames a new file into place, so even two writes in one second
/// give two states.
fn state_string(data_dir: &std::path::Path, account: &str) -> String {
	let Ok(path) = vacation_store::vacation_file(data_dir, account) else {
		return "0".to_string();
	};
	let Ok(meta) = std::fs::metadata(&path) else {
		return "0".to_string();
	};
	let Ok(modified) = meta.modified() else {
		return "0".to_string();
	};
	modified
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_nanos().to_string())
		.unwrap_or_else(|_| "0".to_string())
}

fn method_error(kind: &str, call_id: &str) -> Value {
	json!(["error", { "type": kind }, call_id])
}

fn forbidden_value() -> Value {
	json!({ "type": "forbidden" })
}

/// Validate and merge `patch` into `current`. The result is the new
/// setting to persist. Returning `Err(value)` produces the matching
/// `notUpdated` entry: an `invalidProperties` error with the offending
/// names, or `invalidPatch` when the body is not an object.
fn apply_patch(current: &VacationSetting, patch: &Value) -> Result<VacationSetting, Value> {
	let Some(patch) = patch.as_object() else {
		return Err(json!({ "type": "invalidPatch" }));
	};
	let unknown: Vec<&str> = patch
		.keys()
		.map(String::as_str)
		.filter(|name| !PROPERTIES.contains(name))
		.collect();
	if !unknown.is_empty() {
		return Err(json!({
			"type": "invalidProperties",
			"properties": unknown,
		}));
	}
	let mut bad: Vec<&str> = Vec::new();
	let mut next = current.clone();
	if let Some(value) = patch.get("id")
		&& value.as_str() != Some(SINGLETON_ID)
	{
		bad.push("id");
	}
	if let Some(value) = patch.get("isEnabled") {
		match value.as_bool() {
			Some(b) => next.is_enabled = b,
			None => bad.push("isEnabled"),
		}
	}
	if let Some(value) = patch.get("fromDate") {
		next.from_date = match parse_optional_date(value) {
			Ok(parsed) => parsed,
			Err(()) => {
				bad.push("fromDate");
				None
			}
		};
	}
	if let Some(value) = patch.get("toDate") {
		next.to_date = match parse_optional_date(value) {
			Ok(parsed) => parsed,
			Err(()) => {
				bad.push("toDate");
				None
			}
		};
	}
	if let Some(value) = patch.get("subject") {
		next.subject = match parse_optional_string(value) {
			Ok(parsed) if parsed.as_deref().is_none_or(header_safe) => parsed,
			_ => {
				bad.push("subject");
				None
			}
		};
	}
	if let Some(value) = patch.get("textBody") {
		next.text_body = match parse_optional_string(value) {
			Ok(parsed) => parsed,
			Err(()) => {
				bad.push("textBody");
				None
			}
		};
	}
	if let Some(value) = patch.get("htmlBody") {
		next.html_body = match parse_optional_string(value) {
			Ok(parsed) => parsed,
			Err(()) => {
				bad.push("htmlBody");
				None
			}
		};
	}
	// A body field over the per-server size cap is reported as
	// `invalidProperties` so the client can shorten the value.
	for (key, value) in [("textBody", &next.text_body), ("htmlBody", &next.html_body)] {
		if let Some(body) = value
			&& body.len() > MAX_BODY_BYTES
		{
			bad.push(key);
		}
	}
	if next.from_date.is_some() && next.to_date.is_some() {
		let from = vacation_store::utc_date_to_unix_secs(next.from_date.as_deref());
		let to = vacation_store::utc_date_to_unix_secs(next.to_date.as_deref());
		if let (Some(from), Some(to)) = (from, to)
			&& from > to
		{
			bad.push("fromDate");
			bad.push("toDate");
		}
	}
	if !bad.is_empty() {
		bad.sort_unstable();
		bad.dedup();
		return Err(json!({
			"type": "invalidProperties",
			"properties": bad,
		}));
	}
	Ok(next)
}

fn parse_optional_date(value: &Value) -> Result<Option<String>, ()> {
	if value.is_null() {
		return Ok(None);
	}
	let Some(text) = value.as_str() else {
		return Err(());
	};
	if vacation_store::utc_date_to_unix_secs(Some(text)).is_some() {
		Ok(Some(text.to_string()))
	} else {
		Err(())
	}
}

/// A subject becomes the reply's `Subject:` header: a line break would end
/// it and start a header of the client's choosing, so any control
/// character is refused, as is a value longer than one header line.
fn header_safe(subject: &str) -> bool {
	subject.len() <= MAX_HEADER_VALUE_LEN && !subject.chars().any(char::is_control)
}

fn parse_optional_string(value: &Value) -> Result<Option<String>, ()> {
	if value.is_null() {
		return Ok(None);
	}
	let Some(text) = value.as_str() else {
		return Err(());
	};
	Ok(Some(text.to_string()))
}
