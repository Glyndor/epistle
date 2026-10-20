//! `SieveScript/query` (RFC 9661 section 2.5): filter, sort and page the
//! account's scripts.
//!
//! The filter is `name` (contains, ignoring case) and `isActive`, both
//! optional; the sort is `name` and `isActive`. Filter operators and
//! collations are not supported and are said to be, rather than ignored. An
//! account holds at most [`MAX_SCRIPTS`](crate::managesieve::store::MAX_SCRIPTS)
//! scripts, so the whole query is done in memory over a list that small.

use std::cmp::Ordering;

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::sieve_blob;
use super::sieve_script::{method_error, state_string, store_failure};
use crate::managesieve::store::ScriptInfo;

/// The most sort criteria taken into account.
const MAX_COMPARATORS: usize = 4;

/// A filter the server can run.
#[derive(Default)]
struct Filter {
	name: Option<String>,
	active: Option<bool>,
}

impl Filter {
	fn matches(&self, script: &ScriptInfo) -> bool {
		self.name
			.as_ref()
			.is_none_or(|needle| script.name.to_lowercase().contains(needle))
			&& self.active.is_none_or(|active| script.active == active)
	}
}

/// One sort criterion.
struct Comparator {
	by_active: bool,
	ascending: bool,
}

impl Comparator {
	fn compare(&self, a: &ScriptInfo, b: &ScriptInfo) -> Ordering {
		let order = if self.by_active {
			a.active.cmp(&b.active)
		} else {
			a.name.cmp(&b.name)
		};
		if self.ascending {
			order
		} else {
			order.reverse()
		}
	}
}

fn parse_filter(args: &Value, call_id: &str) -> Result<Filter, Value> {
	let mut filter = Filter::default();
	let object = match args.get("filter") {
		None | Some(Value::Null) => return Ok(filter),
		Some(Value::Object(object)) => object,
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};
	for (key, value) in object {
		match (key.as_str(), value) {
			("name", Value::String(text)) => filter.name = Some(text.to_lowercase()),
			("isActive", Value::Bool(active)) => filter.active = Some(*active),
			("name" | "isActive", _) => return Err(method_error("invalidArguments", call_id)),
			_ => return Err(method_error("unsupportedFilter", call_id)),
		}
	}
	Ok(filter)
}

fn parse_sort(args: &Value, call_id: &str) -> Result<Vec<Comparator>, Value> {
	let items = match args.get("sort") {
		None | Some(Value::Null) => return Ok(Vec::new()),
		Some(Value::Array(items)) => items,
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};
	if items.len() > MAX_COMPARATORS {
		return Err(method_error("unsupportedSort", call_id));
	}
	let mut comparators = Vec::with_capacity(items.len());
	for item in items {
		let Some(object) = item.as_object() else {
			return Err(method_error("invalidArguments", call_id));
		};
		let ascending = match object.get("isAscending") {
			None | Some(Value::Null) => true,
			Some(Value::Bool(ascending)) => *ascending,
			Some(_) => return Err(method_error("invalidArguments", call_id)),
		};
		if object.get("collation").is_some_and(|c| !c.is_null()) {
			return Err(method_error("unsupportedSort", call_id));
		}
		match object.get("property").and_then(Value::as_str) {
			Some("name") => comparators.push(Comparator {
				by_active: false,
				ascending,
			}),
			Some("isActive") => comparators.push(Comparator {
				by_active: true,
				ascending,
			}),
			Some(_) => return Err(method_error("unsupportedSort", call_id)),
			None => return Err(method_error("invalidArguments", call_id)),
		}
	}
	Ok(comparators)
}

/// An optional integer argument.
fn integer(args: &Value, key: &str, call_id: &str) -> Result<Option<i64>, Value> {
	match args.get(key) {
		None | Some(Value::Null) => Ok(None),
		Some(value) => value
			.as_i64()
			.map(Some)
			.ok_or_else(|| method_error("invalidArguments", call_id)),
	}
}

/// `SieveScript/query`.
pub(crate) fn query(state: &ApiState, principal: &Principal, args: &Value, call_id: &str) -> Value {
	match run(state, principal, args, call_id) {
		Ok(response) | Err(response) => response,
	}
}

fn run(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
) -> Result<Value, Value> {
	let account = super::state::admitted_account(state, principal, args, call_id)?;
	let filter = parse_filter(args, call_id)?;
	let mut sort = parse_sort(args, call_id)?;
	let position = integer(args, "position", call_id)?.unwrap_or(0);
	let anchor_offset = integer(args, "anchorOffset", call_id)?.unwrap_or(0);
	let limit = match integer(args, "limit", call_id)? {
		Some(limit) if limit < 0 => return Err(method_error("invalidArguments", call_id)),
		limit => limit,
	};
	let anchor = match args.get("anchor") {
		None | Some(Value::Null) => None,
		Some(Value::String(id)) => Some(id.as_str()),
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};
	let calculate_total = match args.get("calculateTotal") {
		None | Some(Value::Null) => false,
		Some(Value::Bool(flag)) => *flag,
		Some(_) => return Err(method_error("invalidArguments", call_id)),
	};

	let (counter, scripts) = sieve_blob::store(state.data_dir(), &account)
		.snapshot()
		.map_err(|error| store_failure(&error, call_id))?;
	let mut matching: Vec<ScriptInfo> = scripts.into_iter().filter(|s| filter.matches(s)).collect();
	// Whatever the criteria say, equal scripts end up in name order.
	sort.push(Comparator {
		by_active: false,
		ascending: true,
	});
	matching.sort_by(|a, b| {
		sort.iter()
			.map(|comparator| comparator.compare(a, b))
			.find(|order| order.is_ne())
			.unwrap_or(Ordering::Equal)
	});

	let total = matching.len();
	let start = match anchor {
		Some(id) => {
			let at = matching
				.iter()
				.position(|s| s.id == id)
				.ok_or_else(|| method_error("anchorNotFound", call_id))?;
			(at as i64).saturating_add(anchor_offset).max(0)
		}
		None if position < 0 => (total as i64).saturating_add(position).max(0),
		None => position,
	};
	let start = usize::try_from(start).unwrap_or(usize::MAX).min(total);
	let take = limit.map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
	let ids: Vec<&str> = matching
		.iter()
		.skip(start)
		.take(take)
		.map(|s| s.id.as_str())
		.collect();
	let mut response = json!({
		"accountId": account,
		"queryState": state_string(counter),
		"canCalculateChanges": false,
		"position": start,
		"ids": ids,
	});
	if calculate_total {
		response["total"] = json!(total);
	}
	Ok(json!(["SieveScript/query", response, call_id]))
}
