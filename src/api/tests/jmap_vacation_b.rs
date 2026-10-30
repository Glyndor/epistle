//! `VacationResponse` wire tests beyond the round trip: the subject that
//! becomes a header, the account boundary, `ids`, and the state strings a
//! client syncs on.

use axum::Router;
use serde_json::{Value, json};

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use crate::storage::FsSpool;

async fn call(app: &Router, token: &str, method: &str, args: Value) -> Value {
	let req = json!({ "methodCalls": [[method, args, "c1"]] });
	let (_, body) = request_with_body(app, "POST", "/jmap/api", Some(token), Some(req)).await;
	body["methodResponses"][0].clone()
}

async fn set_subject(subject: &str) -> Value {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let args = json!({
		"accountId": "alice",
		"update": { "singleton": { "isEnabled": true, "subject": subject } },
	});
	call(&app, TOKEN.as_str(), "VacationResponse/set", args).await
}

#[tokio::test]
async fn a_subject_with_a_line_break_is_refused() {
	for subject in ["Away\r\nBcc: victim@example.net", "Away\nX: y", "Away\0"] {
		let response = set_subject(subject).await;
		let error = &response[1]["notUpdated"]["singleton"];
		assert_eq!(error["type"], "invalidProperties", "{subject:?}");
		assert_eq!(error["properties"], json!(["subject"]), "{subject:?}");
	}
}

#[tokio::test]
async fn a_subject_longer_than_a_header_line_is_refused() {
	let response = set_subject(&"s".repeat(999)).await;
	let error = &response[1]["notUpdated"]["singleton"];
	assert_eq!(error["properties"], json!(["subject"]));
}

/// `ann` and `bob` on separate domains, and a key bound to `ann` alone. It
/// may send: switching a reply on takes that scope, and these tests are about
/// which account the key reaches, not about scopes (jmap_tests_sieve_scope.rs).
fn ann_only(dir: &std::path::Path) -> (Router, String) {
	let secret = crate::test_fixtures::api_key().to_string();
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("open key store");
	keys.add(crate::api::api_keys::ApiKey {
		label: "ann-only".to_string(),
		hash: crate::api::api_keys::sha256_hash(&secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
		domains: Vec::new(),
		account: Some("ann".to_string()),
	})
	.expect("add key");
	drop(keys);
	let account = |name: &str, address: &str| crate::config::Account {
		display_name: None,
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: Some(crate::smtp::auth::tests::base::hash(
			crate::test_fixtures::password(),
		)),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let domains = vec!["a.example".to_string(), "b.example".to_string()];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![
				account("ann", "ann@a.example"),
				account("bob", "bob@b.example"),
			],
		)
		.expect("open store"),
	);
	let state = crate::api::ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle());
	(router(state), secret)
}

#[tokio::test]
async fn an_account_reads_and_sets_only_its_own_vacation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path());
	let update = |account: &str| {
		json!({
			"accountId": account,
			"update": { "singleton": { "isEnabled": true, "textBody": "Away." } },
		})
	};
	let get = call(
		&app,
		&secret,
		"VacationResponse/get",
		json!({"accountId": "bob"}),
	)
	.await;
	assert_eq!(get[0], "error");
	assert_eq!(get[1]["type"], "accountNotFound");
	let set = call(&app, &secret, "VacationResponse/set", update("bob")).await;
	assert_eq!(set[0], "error");
	assert_eq!(set[1]["type"], "accountNotFound");
	let bob = crate::storage::vacation_store::read(dir.path(), "bob").expect("read bob");
	assert!(!bob.is_enabled, "bob's vacation is untouched");

	let own = call(&app, &secret, "VacationResponse/set", update("ann")).await;
	assert_eq!(own[1]["updated"], json!({ "singleton": null }));
	let ann = crate::storage::vacation_store::read(dir.path(), "ann").expect("read ann");
	assert!(ann.is_enabled, "ann sets her own vacation");
}

#[tokio::test]
async fn get_honours_ids() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let token = TOKEN.as_str();
	let args = json!({ "accountId": "alice", "ids": ["other", "singleton"] });
	let response = call(&app, token, "VacationResponse/get", args).await;
	assert_eq!(response[1]["notFound"], json!(["other"]));
	assert_eq!(response[1]["list"][0]["id"], "singleton");
	let args = json!({ "accountId": "alice", "ids": ["other"] });
	let response = call(&app, token, "VacationResponse/get", args).await;
	assert_eq!(response[1]["list"], json!([]));
	let args = json!({ "accountId": "alice", "ids": null, "properties": ["subject"] });
	let response = call(&app, token, "VacationResponse/get", args).await;
	assert_eq!(
		response[1]["list"][0],
		json!({ "id": "singleton", "subject": null })
	);
}

#[tokio::test]
async fn set_reports_the_state_before_and_after_and_honours_if_in_state() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let token = TOKEN.as_str();
	let before = call(
		&app,
		token,
		"VacationResponse/get",
		json!({"accountId": "alice"}),
	)
	.await;
	let before = before[1]["state"].clone();
	let args = json!({
		"accountId": "alice",
		"update": { "singleton": { "isEnabled": true } },
	});
	let first = call(&app, token, "VacationResponse/set", args.clone()).await;
	assert_eq!(first[1]["oldState"], before);
	assert_ne!(first[1]["newState"], before, "a write moves the state");
	let second = call(&app, token, "VacationResponse/set", args).await;
	assert_ne!(
		second[1]["newState"], first[1]["newState"],
		"two writes in one second still differ"
	);
	let stale = json!({
		"accountId": "alice",
		"ifInState": first[1]["newState"],
		"update": { "singleton": { "isEnabled": false } },
	});
	let response = call(&app, token, "VacationResponse/set", stale).await;
	assert_eq!(response[0], "error");
	assert_eq!(response[1]["type"], "stateMismatch");
	let after = crate::storage::vacation_store::read(dir.path(), "alice").expect("read");
	assert!(after.is_enabled, "a mismatched ifInState changes nothing");
}
