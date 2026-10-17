//! A script that redirects, replies or rejects makes the server send mail
//! when mail arrives, so storing or activating one takes the `send` scope,
//! not only `write` (the scopes are independent: `write` does not send).

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{ann_only, call, store, upload};
use super::tests::TOKEN;

const REDIRECT: &[u8] = b"redirect \"someone@target.example\";\r\n";
const VACATION: &[u8] = b"require \"vacation\";\r\nvacation \"away\";\r\n";
const REJECT: &[u8] = b"require \"reject\";\r\nreject \"no\";\r\n";
const NESTED: &[u8] = b"if true { if not false { redirect :copy \"x@target.example\"; } }\r\n";
const PLAIN: &[u8] = b"require \"fileinto\";\r\nfileinto \"Work\";\r\n";

async fn set(app: &axum::Router, secret: &str, args: Value) -> Value {
	let mut full = json!({"accountId": "ann"});
	full.as_object_mut()
		.expect("object")
		.extend(args.as_object().expect("object").clone());
	call(app, secret, "SieveScript/set", full).await
}

#[tokio::test]
async fn a_key_without_send_cannot_store_a_script_that_sends() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	for script in [REDIRECT, VACATION, REJECT, NESTED] {
		let blob = upload(&app, TOKEN.as_str(), "ann", script).await;
		let response = set(
			&app,
			&secret,
			json!({"create": {"a": {"name": "s", "blobId": blob}}}),
		)
		.await;
		assert_eq!(
			response[1]["notCreated"]["a"]["type"],
			"forbidden",
			"{}",
			String::from_utf8_lossy(script)
		);
	}
	assert!(store(dir.path(), "ann").list().expect("list").is_empty());
	// A script that sends nothing is storable and activatable.
	let blob = upload(&app, TOKEN.as_str(), "ann", PLAIN).await;
	let response = set(
		&app,
		&secret,
		json!({"create": {"a": {"name": "plain", "blobId": blob}}, "onSuccessActivateScript": "#a"}),
	)
	.await;
	assert_eq!(response[1]["created"]["a"]["isActive"], true, "{response}");
}

#[tokio::test]
async fn a_key_without_send_cannot_turn_a_script_into_one_that_sends() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	let plain = store(dir.path(), "ann")
		.create("plain", "keep;\r\n")
		.expect("plain");
	let blob = upload(&app, TOKEN.as_str(), "ann", REDIRECT).await;
	let response = set(
		&app,
		&secret,
		json!({"update": {plain.id.clone(): {"blobId": blob}}}),
	)
	.await;
	assert_eq!(response[1]["notUpdated"][&plain.id]["type"], "forbidden");
	assert_eq!(
		store(dir.path(), "ann").get("plain").expect("get"),
		"keep;\r\n"
	);
	// Renaming one that already sends changes no content, and is allowed.
	let sending = store(dir.path(), "ann")
		.create("sending", "redirect \"a@target.example\";\r\n")
		.expect("sending");
	let renamed = set(
		&app,
		&secret,
		json!({"update": {sending.id.clone(): {"name": "renamed"}}}),
	)
	.await;
	assert_eq!(renamed[1]["updated"][&sending.id], Value::Null, "{renamed}");
}

#[tokio::test]
async fn a_key_without_send_cannot_activate_a_script_that_sends() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	let s = store(dir.path(), "ann");
	let plain = s.create("plain", "keep;\r\n").expect("plain");
	let sending = s
		.create("sending", "redirect \"a@target.example\";\r\n")
		.expect("sending");
	s.set_active(Some("plain")).expect("activate");
	let blob = upload(&app, TOKEN.as_str(), "ann", PLAIN).await;
	let response = set(
		&app,
		&secret,
		json!({
			"create": {"a": {"name": "other", "blobId": blob}},
			"onSuccessActivateScript": sending.id,
		}),
	)
	.await;
	assert_eq!(response[0], "error");
	assert_eq!(response[1]["type"], "forbidden");
	// Nothing at all happened: not the creation, not the activation.
	assert_eq!(s.active_name().as_deref(), Some("plain"));
	assert!(s.get("other").is_err());
	// Deactivating, and activating one that sends nothing, are fine.
	let ok = set(&app, &secret, json!({"onSuccessDeactivateScript": true})).await;
	assert_eq!(ok[1]["updated"][&plain.id], json!({"isActive": false}));
}

#[tokio::test]
async fn a_key_with_send_can_do_all_of_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write", "send"]);
	let blob = upload(&app, TOKEN.as_str(), "ann", REDIRECT).await;
	let response = set(
		&app,
		&secret,
		json!({"create": {"a": {"name": "fwd", "blobId": blob}}, "onSuccessActivateScript": "#a"}),
	)
	.await;
	assert_eq!(response[1]["created"]["a"]["isActive"], true, "{response}");
	assert_eq!(
		store(dir.path(), "ann").active_name().as_deref(),
		Some("fwd")
	);
}
