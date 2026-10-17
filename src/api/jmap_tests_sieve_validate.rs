//! `SieveScript/validate` (RFC 9661 section 2.6).

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{ann_only, app, call, call_as_alice, store, upload};
use super::tests::TOKEN;

/// The response is a `SieveScript/validate` answer, not a method error, and
/// says the script is valid.
fn assert_valid(response: &Value, message: &str) {
	assert_eq!(response[0], "SieveScript/validate", "{message}: {response}");
	assert_eq!(response[1]["error"], Value::Null, "{message}");
}

/// Upload `script` for alice and validate it.
async fn validate(dir: &std::path::Path, script: &[u8]) -> Value {
	let app = app(dir);
	let blob = upload(&app, TOKEN.as_str(), "alice", script).await;
	call_as_alice(
		&app,
		"SieveScript/validate",
		json!({"accountId": "alice", "blobId": blob}),
	)
	.await
}

#[tokio::test]
async fn a_valid_script_has_no_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let response = validate(
		dir.path(),
		b"require \"fileinto\";\r\nfileinto \"Junk\";\r\n",
	)
	.await;
	assert_eq!(response[0], "SieveScript/validate");
	assert_eq!(response[1]["accountId"], "alice");
	assert_valid(&response, "valid");
}

#[tokio::test]
async fn an_invalid_script_is_invalid_sieve_with_the_line() {
	let dir = tempfile::tempdir().expect("tempdir");
	let response = validate(dir.path(), b"keep;\r\nkeep;\r\nif if\r\n").await;
	assert_eq!(
		response[1]["error"],
		json!({"type": "invalidSieve", "description": "line 3: expected '{'"})
	);
}

#[tokio::test]
async fn an_unsupported_extension_is_invalid_sieve() {
	let dir = tempfile::tempdir().expect("tempdir");
	let response = validate(
		dir.path(),
		b"require [\"fileinto\", \"enotify\"];\r\nkeep;\r\n",
	)
	.await;
	assert_eq!(response[1]["error"]["type"], "invalidSieve");
	assert_eq!(
		response[1]["error"]["description"],
		"extension \"enotify\" is not supported"
	);
}

#[tokio::test]
async fn an_empty_script_a_binary_one_and_an_oversized_one_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let empty = validate(dir.path(), b"").await;
	assert_eq!(empty[1]["error"]["type"], "invalidSieve");
	assert_eq!(empty[1]["error"]["description"], "script is empty");
	let binary = validate(dir.path(), &[b'k', b'e', 0xff, 0xfe, b';']).await;
	assert_eq!(binary[1]["error"]["type"], "invalidSieve");
	assert_eq!(
		binary[1]["error"]["description"],
		"script is not valid UTF-8"
	);
	let huge = format!(
		"keep;\r\n#{}\r\n",
		"x".repeat(crate::managesieve::store::MAX_SCRIPT_BYTES)
	);
	let large = validate(dir.path(), huge.as_bytes()).await;
	assert_eq!(large[1]["error"], json!({"type": "tooLarge"}));
}

#[tokio::test]
async fn validating_stores_nothing_and_moves_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let before = store(dir.path(), "alice").state().expect("state");
	validate(dir.path(), b"keep;\r\n").await;
	assert!(store(dir.path(), "alice").list().expect("list").is_empty());
	assert_eq!(store(dir.path(), "alice").state().expect("state"), before);
}

#[tokio::test]
async fn a_reason_does_not_repeat_the_script() {
	let dir = tempfile::tempdir().expect("tempdir");
	let script = format!("\"{}\";", "ATTACKER-TEXT".repeat(500));
	let response = validate(dir.path(), script.as_bytes()).await;
	let description = response[1]["error"]["description"]
		.as_str()
		.expect("description");
	assert!(
		description.len() < 100 && !description.contains("ATTACKER"),
		"{} octets",
		description.len()
	);
}

#[tokio::test]
async fn hostile_shapes_are_answered_not_run_into() {
	let dir = tempfile::tempdir().expect("tempdir");
	let nots = format!("if {}true {{ keep; }}", "not ".repeat(200_000));
	let response = validate(dir.path(), nots.as_bytes()).await;
	assert_eq!(
		response[1]["error"]["description"],
		"line 1: nested more than 64 levels deep"
	);
	let blocks = "if true {".repeat(100_000);
	let response = validate(dir.path(), blocks.as_bytes()).await;
	assert_eq!(response[1]["error"]["type"], "invalidSieve");
	// A script of nothing but short commands is the most work the size limit
	// allows; it is checked in one pass.
	let commands = "keep;\n".repeat(crate::managesieve::store::MAX_SCRIPT_BYTES / 6);
	let response = validate(dir.path(), commands.as_bytes()).await;
	assert_valid(&response, "valid");
}

#[tokio::test]
async fn a_missing_blob_and_missing_arguments_are_method_errors() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let missing = call_as_alice(
		&app,
		"SieveScript/validate",
		json!({"accountId": "alice", "blobId": "0190e9d2-7b1c-7000-8000-000000000000"}),
	)
	.await;
	assert_eq!(missing[1]["type"], "blobNotFound");
	for args in [
		json!({"accountId": "alice"}),
		json!({"accountId": "alice", "blobId": 1}),
		json!({"blobId": "x"}),
	] {
		let response = call_as_alice(&app, "SieveScript/validate", args.clone()).await;
		assert_eq!(response[1]["type"], "invalidArguments", "{args}");
	}
}

#[tokio::test]
async fn another_accounts_blob_is_not_there() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	let bobs = upload(&app, TOKEN.as_str(), "bob", b"keep;\r\n").await;
	let anns = upload(&app, TOKEN.as_str(), "ann", b"keep;\r\n").await;
	let stolen = call(
		&app,
		&secret,
		"SieveScript/validate",
		json!({"accountId": "ann", "blobId": bobs}),
	)
	.await;
	assert_eq!(stolen[1]["type"], "blobNotFound");
	let blocked = call(
		&app,
		&secret,
		"SieveScript/validate",
		json!({"accountId": "bob", "blobId": bobs}),
	)
	.await;
	assert_eq!(blocked[1]["type"], "accountNotFound");
	let own = call(
		&app,
		&secret,
		"SieveScript/validate",
		json!({"accountId": "ann", "blobId": anns}),
	)
	.await;
	assert_valid(&own, "valid");
}

#[tokio::test]
async fn validate_needs_the_read_scope_and_no_more() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read"]);
	let blob = upload(&app, TOKEN.as_str(), "ann", b"keep;\r\n").await;
	let allowed = call(
		&app,
		&secret,
		"SieveScript/validate",
		json!({"accountId": "ann", "blobId": blob}),
	)
	.await;
	assert_valid(&allowed, "a read-only key can validate");
	let other = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(other.path(), &["write"]);
	let blob = upload(&app, TOKEN.as_str(), "ann", b"keep;\r\n").await;
	let denied = call(
		&app,
		&secret,
		"SieveScript/validate",
		json!({"accountId": "ann", "blobId": blob}),
	)
	.await;
	assert_eq!(denied[1]["type"], "forbidden");
}
