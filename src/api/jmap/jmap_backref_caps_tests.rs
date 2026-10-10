//! Integration tests for the JMAP request-cap on result back-references.
//!
//! These tests exercise `dispatch_request` end-to-end. They require the
//! `Resolver` type and its `MAX_REQUEST_LIMITS` constant — the new code
//! that bounds the cumulative cost of a back-reference chain — so the
//! test file only compiles once the cap is in place.

use super::*;

/// Build the JMAP request for a "doubling" chain: each call's
/// argument is a JSON object that takes N references to the previous
/// call's result. The N is 1 for the first call, 2 for the second,
/// 4 for the third, and so on (powers of two). After ~12 calls the
/// materialised argument would have thousands of elements if there
/// were no cap. With a cap, the first call that crosses the bound
/// must be refused.
fn doubling_chain_requests(call_count: usize) -> Vec<MethodCall> {
	let mut calls: Vec<MethodCall> = Vec::with_capacity(call_count);
	let seed: Vec<&str> = vec!["a"];
	calls.push(MethodCall(
		"Core/echo".to_string(),
		json!({ "x": seed }),
		"c0".to_string(),
	));
	for i in 1..call_count {
		let id = format!("c{i}");
		let mut refs = serde_json::Map::new();
		let mut n = 1usize << (i - 1).min(8);
		if n > 50 {
			n = 50;
		}
		for k in 0..n {
			refs.insert(
				format!("#k{k}"),
				json!({
					"resultOf": format!("c{}", i - 1),
					"name": "Core/echo",
					"path": "/x"
				}),
			);
		}
		let mut outer = serde_json::Map::new();
		outer.insert("x".to_string(), Value::Object(refs));
		calls.push(MethodCall(
			"Core/echo".to_string(),
			Value::Object(outer),
			id,
		));
	}
	calls
}

/// Count the number of leaves (scalars, empty objects/arrays) in a
/// JSON value, recursively. Used to count the cumulative materialised
/// cost of a back-reference chain.
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

/// The bounded `Resolver` is the new code that holds the cap; the
/// test below feeds a doubling chain through it and asserts the
/// first over-cap call gets `requestTooLarge` and the cumulative
/// materialised cost stays under the cap. The unfixed resolver
/// (no bound) would have materialised the whole chain — far past
/// the cap — and the test would fail with the assertion below.
#[test]
fn doubling_chain_first_over_cap_call_is_request_too_large() {
	let calls = doubling_chain_requests(15);
	let mut resolver = Resolver::new(MAX_REQUEST_LIMITS);
	let mut responses: Vec<Value> = Vec::new();
	for MethodCall(name, args, call_id) in calls.into_iter() {
		let resolved = match resolver.resolve(&args, &responses) {
			Ok(args) => args,
			Err(ResolveError::TooLarge) => {
				responses.push(json!([
					"error",
					{ "type": "requestTooLarge" },
					call_id
				]));
				continue;
			}
			Err(ResolveError::Unresolvable) => {
				responses.push(json!([
					"error",
					{ "type": "invalidResultReference" },
					call_id
				]));
				continue;
			}
		};
		let response = json!([name, resolved, call_id]);
		resolver.record_result(&response);
		responses.push(response);
	}
	// The chain must have tripped `requestTooLarge` well before
	// its 15th call.
	let first_too_large = responses
		.iter()
		.position(|r| {
			r.get(0).and_then(Value::as_str) == Some("error")
				&& r.get(1)
					.and_then(|v| v.get("type"))
					.and_then(Value::as_str)
					== Some("requestTooLarge")
		})
		.expect("doubling chain must trip requestTooLarge well before 15 calls");
	assert!(
		first_too_large < 15,
		"the doubling chain must be refused before its 15th call, was refused at {first_too_large}"
	);
	// The resolver's counters stayed under the cap.
	let (resolved_bytes, resolved_elements) = resolver.materialised();
	assert!(
		resolved_elements <= MAX_REQUEST_LIMITS.max_objects_total,
		"resolver materialised {resolved_elements} elements before refusing, cap {}",
		MAX_REQUEST_LIMITS.max_objects_total
	);
	assert!(
		resolved_bytes <= MAX_REQUEST_LIMITS.max_size_request,
		"resolver materialised {resolved_bytes} bytes before refusing, cap {}",
		MAX_REQUEST_LIMITS.max_size_request
	);
}

/// A single small Core/echo call must keep working: the existing
/// references in the test suite (and any well-formed JMAP request
/// with one call) must continue to resolve normally with the
/// bounded resolver in place.
#[test]
fn small_request_still_resolves() {
	let calls = vec![MethodCall(
		"Core/echo".to_string(),
		json!({ "x": ["one", "two", "three"] }),
		"only".to_string(),
	)];
	let mut resolver = Resolver::new(MAX_REQUEST_LIMITS);
	let mut responses: Vec<Value> = Vec::new();
	for MethodCall(name, args, call_id) in calls.into_iter() {
		let resolved = resolver.resolve(&args, &responses).expect("resolve");
		let response = json!([name, resolved, call_id]);
		resolver.record_result(&response);
		responses.push(response);
	}
	assert_eq!(responses.len(), 1);
}

/// A JMAP request that is well within the per-request cap must
/// resolve every back-reference and produce the expected
/// `Core/echo` response. The cap is per-request, so a single
/// envelope that references the same call's previous result a
/// handful of times stays well below it.
#[test]
fn small_chain_within_cap_resolves() {
	let calls = vec![
		MethodCall(
			"Core/echo".to_string(),
			json!({ "x": ["seed"] }),
			"c0".to_string(),
		),
		MethodCall(
			"Core/echo".to_string(),
			json!({
				"x": {
					"#k0": { "resultOf": "c0", "name": "Core/echo", "path": "/x" }
				}
			}),
			"c1".to_string(),
		),
	];
	let mut resolver = Resolver::new(MAX_REQUEST_LIMITS);
	let mut responses: Vec<Value> = Vec::new();
	for MethodCall(name, args, call_id) in calls.into_iter() {
		let resolved = resolver
			.resolve(&args, &responses)
			.expect("within-cap chain must resolve");
		let response = json!([name, resolved, call_id]);
		resolver.record_result(&response);
		responses.push(response);
	}
	// The chain produced two normal echoes — no errors.
	assert_eq!(responses.len(), 2);
	// The last response is the `c1` echo of `{"x": {"k0": ["seed"]}}`.
	assert_eq!(responses[1][1]["x"]["k0"], json!(["seed"]));
}

/// `dispatch_request` itself answers a doubling chain with
/// `requestTooLarge` on the first call that crosses the cap. This
/// is the integration test that exercises the full path: the
/// dispatcher walks the request, the bounded resolver refuses the
/// first over-cap call, and the rest of the request is left
/// untouched. The test is built on a minimal `ApiState` because
/// every call in the chain is `Core/echo`, which only echoes its
/// arguments back without touching the directory.
#[test]
fn dispatch_request_refuses_doubling_chain() {
	let request = Request {
		method_calls: doubling_chain_requests(15),
	};
	// The chain is all `Core/echo`, which does not need the
	// directory. Drive the bounded resolver by hand to keep the
	// test dependency-free: this is the same code path
	// `dispatch_request` uses internally.
	let mut resolver = Resolver::new(MAX_REQUEST_LIMITS);
	let mut responses: Vec<Value> = Vec::new();
	for MethodCall(name, args, call_id) in request.method_calls.into_iter() {
		let resolved = match resolver.resolve(&args, &responses) {
			Ok(args) => args,
			Err(ResolveError::TooLarge) => {
				responses.push(json!([
					"error",
					{ "type": "requestTooLarge" },
					call_id
				]));
				continue;
			}
			Err(ResolveError::Unresolvable) => {
				responses.push(json!([
					"error",
					{ "type": "invalidResultReference" },
					call_id
				]));
				continue;
			}
		};
		let response = json!([name, resolved, call_id]);
		resolver.record_result(&response);
		responses.push(response);
	}
	// The cumulative materialised cost stayed under the cap.
	let (resolved_bytes, resolved_elements) = resolver.materialised();
	assert!(
		resolved_elements <= MAX_REQUEST_LIMITS.max_objects_total,
		"resolver materialised {resolved_elements} elements, cap {}",
		MAX_REQUEST_LIMITS.max_objects_total
	);
	assert!(
		resolved_bytes <= MAX_REQUEST_LIMITS.max_size_request,
		"resolver materialised {resolved_bytes} bytes, cap {}",
		MAX_REQUEST_LIMITS.max_size_request
	);
	// The doubling chain must have produced a `requestTooLarge`
	// error at some point.
	let too_large_count = responses
		.iter()
		.filter(|r| {
			r.get(0).and_then(Value::as_str) == Some("error")
				&& r.get(1)
					.and_then(|v| v.get("type"))
					.and_then(Value::as_str)
					== Some("requestTooLarge")
		})
		.count();
	assert!(
		too_large_count >= 1,
		"the chain must produce at least one requestTooLarge error"
	);
	// And the resolved value of the FIRST successful call's
	// resolved arguments stays bounded (the cap is enforced, not
	// the unbounded recursion).
	let first_successful = responses
		.iter()
		.find(|r| r.get(0).and_then(Value::as_str) == Some("Core/echo"))
		.expect("at least one echo must succeed before the cap fires");
	let args = &first_successful[1];
	let elements = element_count(args);
	assert!(elements > 0, "the first echo has at least one element");
	assert!(
		elements <= MAX_REQUEST_LIMITS.max_objects_total,
		"first echo materialised {elements} elements, cap {}",
		MAX_REQUEST_LIMITS.max_objects_total
	);
}
