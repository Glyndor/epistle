//! The `urn:ietf:params:jmap:sieve` capability (RFC 9661 section 1.2.1):
//! what it says is what ManageSieve and the store enforce.

use serde_json::{Value, json};

use super::router;
use super::tests::{TOKEN, request, test_state};

const CAPABILITY: &str = "urn:ietf:params:jmap:sieve";

async fn session() -> Value {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	request(&app, "GET", "/jmap/session", Some(TOKEN.as_str()))
		.await
		.1
}

#[tokio::test]
async fn the_session_names_the_implementation() {
	let session = session().await;
	let implementation = session["capabilities"][CAPABILITY]["implementation"]
		.as_str()
		.expect("implementation is a string");
	assert_eq!(
		implementation,
		format!("epistle {}", env!("CARGO_PKG_VERSION"))
	);
}

#[tokio::test]
async fn every_account_advertises_the_limits_the_store_enforces() {
	use crate::managesieve::store::{MAX_NAME_BYTES, MAX_SCRIPT_BYTES, MAX_SCRIPTS};
	let session = session().await;
	let capability = &session["accounts"]["alice"]["accountCapabilities"][CAPABILITY];
	assert_eq!(capability["maxSizeScriptName"], json!(MAX_NAME_BYTES));
	assert_eq!(capability["maxSizeScript"], json!(MAX_SCRIPT_BYTES));
	assert_eq!(capability["maxNumberScripts"], json!(MAX_SCRIPTS));
	assert_eq!(
		capability["maxNumberRedirects"],
		json!(crate::sieve::interp::MAX_REDIRECTS)
	);
	assert_eq!(capability["notificationMethods"], Value::Null);
	assert_eq!(capability["externalLists"], Value::Null);
}

#[tokio::test]
async fn the_extensions_are_the_ones_managesieve_advertises() {
	let session = session().await;
	let advertised: Vec<&str> =
		session["accounts"]["alice"]["accountCapabilities"][CAPABILITY]["sieveExtensions"]
			.as_array()
			.expect("a list")
			.iter()
			.map(|name| name.as_str().expect("a string"))
			.collect();
	let managesieve: Vec<&str> = crate::managesieve::session::SIEVE_EXTENSIONS
		.split_whitespace()
		.collect();
	assert!(!advertised.is_empty());
	assert_eq!(advertised, managesieve);
}

#[tokio::test]
async fn the_sieve_account_is_the_primary_account() {
	let session = session().await;
	assert_eq!(session["primaryAccounts"][CAPABILITY], "alice");
}
