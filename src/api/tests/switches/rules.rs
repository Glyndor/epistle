//! What sends on its own, set up over JMAP, under the send switch: a vacation
//! reply that is on and a Sieve script that redirects, replies or rejects.

use serde_json::{Value, json};

use super::super::base::TOKEN;
use super::super::sieve::jmap_sieve_support::{call, upload};
use super::support::{OFF, ON, app};

const REDIRECT: &[u8] = b"redirect \"someone@target.example\";\r\n";
const PLAIN: &[u8] = b"require \"fileinto\";\r\nfileinto \"Work\";\r\n";

async fn vacation(app: &axum::Router, account: &str, enabled: bool) -> Value {
	call(
		app,
		TOKEN.as_str(),
		"VacationResponse/set",
		json!({"accountId": account, "update": {"singleton": {
			"isEnabled": enabled, "textBody": "away",
		}}}),
	)
	.await
}

async fn create_script(app: &axum::Router, account: &str, script: &[u8]) -> Value {
	let blob = upload(app, TOKEN.as_str(), account, script).await;
	call(
		app,
		TOKEN.as_str(),
		"SieveScript/set",
		json!({"accountId": account, "create": {"a": {"name": "s", "blobId": blob}}}),
	)
	.await
}

#[tokio::test]
async fn a_vacation_reply_cannot_be_turned_on_for_an_account_with_sending_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let response = vacation(&app, OFF, true).await;
	let refused = &response[1]["notUpdated"]["singleton"];
	assert_eq!(refused["type"], "forbidden", "{response}");
	assert_eq!(
		refused["description"],
		"a vacation reply that is on is not possible, sending is turned off for this account"
	);
	// Turning it off is not sending, so it is allowed.
	let response = vacation(&app, OFF, false).await;
	assert!(response[1]["updated"]["singleton"].is_null(), "{response}");
	assert!(
		response[1]["notUpdated"]["singleton"].is_null(),
		"{response}"
	);
}

#[tokio::test]
async fn a_vacation_reply_can_be_turned_on_for_an_account_that_sends() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let response = vacation(&app, ON, true).await;
	assert!(
		response[1]["notUpdated"]["singleton"].is_null(),
		"{response}"
	);
}

#[tokio::test]
async fn a_script_that_redirects_cannot_be_stored_for_an_account_with_sending_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let response = create_script(&app, OFF, REDIRECT).await;
	let refused = &response[1]["notCreated"]["a"];
	assert_eq!(refused["type"], "forbidden", "{response}");
	assert_eq!(
		refused["description"],
		"a script that redirects, replies or rejects is not possible, sending is turned off for this account"
	);
	// A script that only files mail sends nothing and is stored.
	let response = create_script(&app, OFF, PLAIN).await;
	assert!(response[1]["created"]["a"]["id"].is_string(), "{response}");
}

#[tokio::test]
async fn the_same_script_is_stored_for_an_account_that_sends() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let response = create_script(&app, ON, REDIRECT).await;
	assert!(response[1]["created"]["a"]["id"].is_string(), "{response}");
}
