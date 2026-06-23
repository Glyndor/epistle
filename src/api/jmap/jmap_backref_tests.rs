//! Unit tests for JMAP result back-reference resolution (RFC 8620 §3.7).

use super::*;

/// A prior response triple `[name, arguments, callId]`.
fn response(name: &str, args: Value, call_id: &str) -> Value {
	json!([name, args, call_id])
}

#[test]
fn resolves_simple_pointer_reference() {
	let prior = vec![response(
		"Email/query",
		json!({ "ids": ["a", "b", "c"] }),
		"q1",
	)];
	let args = json!({
		"accountId": "x",
		"#ids": { "resultOf": "q1", "name": "Email/query", "path": "/ids" }
	});
	let resolved = resolve_references(args, &prior).expect("resolve");
	assert_eq!(resolved["ids"], json!(["a", "b", "c"]));
	// The `#`-prefixed key is consumed.
	assert!(resolved.get("#ids").is_none());
	assert_eq!(resolved["accountId"], "x");
}

#[test]
fn wildcard_maps_over_a_list() {
	let prior = vec![response(
		"Email/get",
		json!({ "list": [{ "threadId": "t1" }, { "threadId": "t2" }] }),
		"g1",
	)];
	let args = json!({
		"#ids": { "resultOf": "g1", "name": "Email/get", "path": "/list/*/threadId" }
	});
	let resolved = resolve_references(args, &prior).expect("resolve");
	assert_eq!(resolved["ids"], json!(["t1", "t2"]));
}

#[test]
fn unresolvable_reference_is_an_error() {
	let prior = vec![response("Email/query", json!({ "ids": [] }), "q1")];
	// Wrong callId.
	let args = json!({
		"#ids": { "resultOf": "other", "name": "Email/query", "path": "/ids" }
	});
	assert!(resolve_references(args, &prior).is_err());
	// Wrong method name.
	let args = json!({
		"#ids": { "resultOf": "q1", "name": "Mailbox/get", "path": "/ids" }
	});
	assert!(resolve_references(json!(args), &prior).is_err());
	// Path points nowhere.
	let args = json!({
		"#ids": { "resultOf": "q1", "name": "Email/query", "path": "/missing" }
	});
	assert!(resolve_references(args, &prior).is_err());
}

#[test]
fn no_references_passes_through() {
	let args = json!({ "accountId": "x", "ids": ["a"] });
	let resolved = resolve_references(args.clone(), &[]).expect("resolve");
	assert_eq!(resolved, args);
}
