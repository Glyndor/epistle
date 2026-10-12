//! The back-reference resolver for the JMAP method dispatcher.
//!
//! A JMAP request envelope can carry a chain of `#`-prefixed arguments,
//! where each call's argument references the result of a previous one
//! (RFC 8620 §3.7). The resolver walks those references, substitutes the
//! resolved value in place of the `#`-key, and bounds the cumulative
//! materialised size of the chain so a chain that doubles the payload on
//! every step (the classic reference-loop abuse) cannot blow past the
//! per-request cap the Session advertises.

use serde_json::Value;

use super::MAX_SIZE_REQUEST;

/// Per-request limits used by the back-reference resolver. Mirrors the
/// values advertised in the Session resource (RFC 8620 §6.1): the
/// `maxSizeRequest` byte cap and the sum of `maxObjectsInGet` and
/// `maxObjectsInSet`. A request whose chain of `#`-prefixed arguments
/// would materialise more than this is refused with `requestTooLarge`
/// on the first call that crosses the bound.
pub(crate) struct RequestLimits {
	/// Cumulative bytes of resolved arguments across the request. A
	/// request whose chain would materialise more than this is
	/// rejected on the first call that crosses the bound.
	pub max_size_request: u64,
	/// Cumulative element count of resolved arguments across the
	/// request. Mirrors the spec's `maxObjectsInGet + maxObjectsInSet`
	/// cap; a request whose chain would materialise more leaves than
	/// this is rejected the same way.
	pub max_objects_total: u64,
}

/// The default per-request limits, matching the Session resource.
pub(crate) const MAX_REQUEST_LIMITS: RequestLimits = RequestLimits {
	// The Session's `maxSizeRequest`.
	max_size_request: MAX_SIZE_REQUEST as u64,
	// maxObjectsInGet (500) + maxObjectsInSet (500). The cap is on
	// total resolved leaves, not on objects returned by a single
	// method, so this is the conservative sum.
	max_objects_total: 200,
};

/// Count the number of leaves (scalars, empty objects/arrays) in a
/// JSON value, recursively. Used by the resolver to bound a chain of
/// `#`-prefixed arguments: a back-reference loop that doubles the
/// materialised size every call would, without this bound, blow past
/// any reasonable cap.
fn element_count(value: &Value) -> u64 {
	match value {
		Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 1,
		Value::Array(items) => {
			if items.is_empty() {
				1
			} else {
				items.iter().map(element_count).sum()
			}
		}
		Value::Object(map) => {
			if map.is_empty() {
				1
			} else {
				map.values().map(element_count).sum()
			}
		}
	}
}

/// Byte size of a JSON value when serialised, in bytes. Used by the
/// resolver to bound a chain of back-references against
/// `maxSizeRequest`. `serde_json::to_vec` is the canonical answer; we
/// use it to keep the accounting honest with what the wire would see.
fn byte_size(value: &Value) -> u64 {
	serde_json::to_vec(value)
		.map(|v| v.len() as u64)
		.unwrap_or(0)
}

/// A request-scoped counter that bounds the cumulative work the
/// back-reference resolver does for a single JMAP request. Without
/// this, a request of N `Core/echo` calls each carrying two
/// references to the previous result would double the materialised
/// data N times, so 25 calls could push a few KB into hundreds of MB
/// the request would be processed and the answer would be huge.
/// The resolver instead refuses the first call that crosses either
/// bound with `requestTooLarge` (RFC 8620 §3.7.2 / §3.6.2).
pub(crate) struct Resolver {
	limits: RequestLimits,
	/// Cumulative resolved bytes materialised so far in the request.
	resolved_bytes: u64,
	/// Cumulative resolved elements materialised so far in the
	/// request.
	resolved_elements: u64,
}

impl Resolver {
	/// Build a resolver that enforces the given limits.
	pub fn new(limits: RequestLimits) -> Self {
		Self {
			limits,
			resolved_bytes: 0,
			resolved_elements: 0,
		}
	}

	/// Bytes and elements materialised so far. Read by the dispatcher
	/// when it needs to attribute work to a particular call.
	#[cfg(test)]
	pub fn materialised(&self) -> (u64, u64) {
		(self.resolved_bytes, self.resolved_elements)
	}

	/// Record the cost of a method response just produced, so the next
	/// call's references resolve against a counter that already
	/// includes the new bytes.
	pub fn record_result(&mut self, response: &Value) {
		if let Some(args) = response.get(1) {
			self.resolved_bytes = self.resolved_bytes.saturating_add(byte_size(args));
			self.resolved_elements = self.resolved_elements.saturating_add(element_count(args));
		}
	}

	/// Resolve the `#`-prefixed arguments of `args` against the
	/// accumulated `prior` responses. The two failure modes have
	/// distinct sentinels: `Ok` for a fully resolved `Value`,
	/// `Err(ResolveError::TooLarge)` when materialising this value
	/// would push the request over the per-request limits, and
	/// `Err(ResolveError::Unresolvable)` when a reference points to a
	/// missing call. The dispatcher turns each into the matching
	/// JMAP error type.
	pub fn resolve(&mut self, args: &Value, prior: &[Value]) -> Result<Value, ResolveError> {
		let mut args = args.clone();
		// Walk the whole argument tree for `#`-prefixed keys. JMAP
		// `ResultReference` values can appear at any depth; a chain
		// whose references are nested inside a wrapper key like
		// `{"x": {#k0: ref, #k1: ref}}` would otherwise slip past the
		// bound.
		let mut additions: Vec<(String, Value, u64, u64)> = Vec::new();
		match resolve_references_recursive(&mut args, prior, &mut additions) {
			Ok(true) => {}
			Ok(false) => return Err(ResolveError::Unresolvable),
			Err(()) => return Err(ResolveError::Unresolvable),
		}
		// Sum the per-reference cost; the whole call's materialised
		// value is the cap-relevant quantity.
		let total_bytes: u64 = additions.iter().map(|(_, _, b, _)| *b).sum();
		let total_elements: u64 = additions.iter().map(|(_, _, _, e)| *e).sum();
		if self.resolved_bytes.saturating_add(total_bytes) > self.limits.max_size_request
			|| self.resolved_elements.saturating_add(total_elements) > self.limits.max_objects_total
		{
			return Err(ResolveError::TooLarge);
		}
		self.resolved_bytes = self.resolved_bytes.saturating_add(total_bytes);
		self.resolved_elements = self.resolved_elements.saturating_add(total_elements);
		Ok(args)
	}
}

/// Recursively walk `value` looking for `#`-prefixed keys. Each match
/// resolves the `ResultReference` against `prior`, appends the cost
/// to `additions`, and substitutes the resolved value (with the
/// prefix stripped) in place. Returns `Ok(true)` on success,
/// `Ok(false)` when a reference cannot be resolved.
fn resolve_references_recursive(
	value: &mut Value,
	prior: &[Value],
	additions: &mut Vec<(String, Value, u64, u64)>,
) -> Result<bool, ()> {
	match value {
		Value::Object(map) => {
			let refs: Vec<String> = map
				.keys()
				.filter(|key| key.starts_with('#'))
				.cloned()
				.collect();
			for key in refs {
				let reference = map.remove(&key).expect("key present");
				let resolved = match resolve_reference(&reference, prior) {
					Some(r) => r,
					None => return Ok(false),
				};
				let bytes = byte_size(&resolved);
				let elements = element_count(&resolved);
				additions.push((key.clone(), resolved.clone(), bytes, elements));
				map.insert(key[1..].to_string(), resolved);
			}
			let keys: Vec<String> = map.keys().cloned().collect();
			for k in keys {
				if let Some(v) = map.get_mut(&k)
					&& !resolve_references_recursive(v, prior, additions)?
				{
					return Ok(false);
				}
			}
			Ok(true)
		}
		Value::Array(items) => {
			for item in items.iter_mut() {
				if !resolve_references_recursive(item, prior, additions)? {
					return Ok(false);
				}
			}
			Ok(true)
		}
		_ => Ok(true),
	}
}

/// Failure modes for the bounded resolver; the dispatcher maps each
/// to the matching JMAP error type (`requestTooLarge` or
/// `invalidResultReference`).
#[derive(Debug)]
pub(crate) enum ResolveError {
	/// Adding the resolved value would push the cumulative bytes or
	/// element count over the per-request cap. The first call that
	/// crosses the bound is rejected.
	TooLarge,
	/// A `#ResultOf` reference pointed at a missing call or path.
	Unresolvable,
}

/// Resolve one ResultReference `{resultOf, name, path}` against the prior
/// `[name, arguments, callId]` responses.
fn resolve_reference(reference: &Value, prior: &[Value]) -> Option<Value> {
	let result_of = reference.get("resultOf")?.as_str()?;
	let name = reference.get("name")?.as_str()?;
	let path = reference.get("path")?.as_str()?;
	let response = prior.iter().find(|response| {
		response.get(0).and_then(Value::as_str) == Some(name)
			&& response.get(2).and_then(Value::as_str) == Some(result_of)
	})?;
	pointer_with_wildcard(response.get(1)?, path)
}

/// JSON Pointer (RFC 6901) extended with the JMAP `*` wildcard: a `/*` segment
/// maps the rest of the path over an array, flattening one level of array
/// results (RFC 8620 §3.7).
fn pointer_with_wildcard(value: &Value, path: &str) -> Option<Value> {
	let Some(star) = path.find("/*") else {
		return value.pointer(path).cloned();
	};
	let (before, rest) = path.split_at(star);
	let rest = &rest[2..]; // drop the "/*"
	let array = value.pointer(before)?.as_array()?;
	let mut out = Vec::new();
	for item in array {
		let resolved = if rest.is_empty() {
			item.clone()
		} else {
			pointer_with_wildcard(item, rest)?
		};
		match resolved {
			Value::Array(items) => out.extend(items),
			other => out.push(other),
		}
	}
	Some(Value::Array(out))
}

/// Replace each `#`-prefixed argument (a ResultReference) with the value pulled
/// from an earlier method's result, per RFC 8620 §3.7. The unbounded
/// version kept for unit tests; the production dispatcher goes through
/// `Resolver::resolve` instead so it can bound the cumulative cost.
#[cfg(test)]
pub(crate) fn resolve_references(mut args: Value, prior: &[Value]) -> Result<Value, ()> {
	let Some(object) = args.as_object_mut() else {
		return Ok(args);
	};
	let references: Vec<String> = object
		.keys()
		.filter(|key| key.starts_with('#'))
		.cloned()
		.collect();
	for key in references {
		let reference = object.remove(&key).expect("key present");
		let resolved = resolve_reference(&reference, prior).ok_or(())?;
		object.insert(key[1..].to_string(), resolved);
	}
	Ok(args)
}

#[cfg(test)]
#[path = "dispatcher_backref_tests.rs"]
mod backref_tests;

#[cfg(test)]
#[path = "dispatcher_backref_caps_tests.rs"]
mod backref_caps_tests;
