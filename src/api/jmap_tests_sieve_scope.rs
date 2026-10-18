//! A script that redirects, replies or rejects makes the server send mail
//! when mail arrives, so storing or activating one takes the `send` scope,
//! not only `write` (the scopes are independent: `write` does not send).

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{ann_only, call, store, upload};
use super::tests::TOKEN;

const REDIRECT: &[u8] = b"redirect \"someone@target.example\";\r\n";
const VACATION: &[u8] = b"require \"vacation\";\r\nvacation \"away\";\r\n";
const REJECT: &[u8] = b"require \"reject\";\r\nreject \"no\";\r\n";
const EREJECT: &[u8] = b"require \"ereject\";\r\nereject \"no\";\r\n";
/// Identifiers are not case-sensitive in Sieve (RFC 5228 section 2.1).
const SHOUTED: &[u8] = b"REDIRECT \"someone@target.example\";\r\n";
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
	for script in [REDIRECT, VACATION, REJECT, EREJECT, SHOUTED, NESTED] {
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

async fn vacation_set(app: &axum::Router, secret: &str, patch: Value) -> Value {
	call(
		app,
		secret,
		"VacationResponse/set",
		json!({"accountId": "ann", "update": {"singleton": patch}}),
	)
	.await
}

async fn vacation_get(app: &axum::Router, secret: &str) -> Value {
	call(
		app,
		secret,
		"VacationResponse/get",
		json!({"accountId": "ann"}),
	)
	.await[1]["list"][0]
		.clone()
}

#[tokio::test]
async fn a_key_without_send_cannot_switch_the_vacation_reply_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	let response = vacation_set(
		&app,
		&secret,
		json!({"isEnabled": true, "textBody": "away"}),
	)
	.await;
	assert_eq!(
		response[1]["notUpdated"]["singleton"]["type"], "forbidden",
		"{response}"
	);
	assert_eq!(response[1]["updated"], json!({}));
	assert_eq!(vacation_get(&app, &secret).await["isEnabled"], false);
	// Writing the text while it stays off is storing a setting, not sending.
	let response = vacation_set(&app, &secret, json!({"textBody": "away"})).await;
	assert_eq!(
		response[1]["updated"]["singleton"],
		Value::Null,
		"{response}"
	);
}

#[tokio::test]
async fn a_key_without_send_cannot_change_a_vacation_reply_that_is_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The reply was switched on by someone who may send.
	crate::storage::vacation_store::write(
		dir.path(),
		"ann",
		&crate::storage::vacation_store::VacationSetting {
			is_enabled: true,
			text_body: Some("away".to_string()),
			..crate::storage::vacation_store::VacationSetting::disabled()
		},
	)
	.expect("seed");
	let (app2, plain) = ann_only(dir.path(), &["read", "write"]);
	let changed = vacation_set(&app2, &plain, json!({"textBody": "other words"})).await;
	assert_eq!(
		changed[1]["notUpdated"]["singleton"]["type"], "forbidden",
		"{changed}"
	);
	// Switching it off is always allowed.
	let off = vacation_set(&app2, &plain, json!({"isEnabled": false})).await;
	assert_eq!(off[1]["updated"]["singleton"], Value::Null, "{off}");
	assert_eq!(vacation_get(&app2, &plain).await["isEnabled"], false);
}

#[tokio::test]
async fn a_key_with_send_can_switch_the_vacation_reply_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write", "send"]);
	let response = vacation_set(
		&app,
		&secret,
		json!({"isEnabled": true, "textBody": "away"}),
	)
	.await;
	assert_eq!(
		response[1]["updated"]["singleton"],
		Value::Null,
		"{response}"
	);
	assert_eq!(vacation_get(&app, &secret).await["isEnabled"], true);
}
