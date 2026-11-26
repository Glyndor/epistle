//! `Email/set` create and `Email/copy` of one account at the same moment:
//! the quota check and the write are one step under the account's admission
//! lock, so requests that arrive together share a single admission.

use super::base::{request_with_body, test_state};
use super::jmap_email_create::create;
use super::router;
use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Barrier;

const KEY: &str = "race-key-0123456789abcdef";
const REQUESTS: usize = 8;
const ROUNDS: usize = 12;
const FITS: usize = 3;

fn draft() -> Value {
	json!({
		"mailboxIds": {"INBOX": true},
		"from": [{"email": "alice@example.org"}],
		"to": [{"email": "bob@elsewhere.example"}],
		"subject": "Built",
		"textBody": [{"partId": "t"}],
		"bodyValues": {"t": {"value": "x".repeat(3_000)}},
	})
}

/// The stored size of one draft, as the response of a first create says.
async fn draft_size() -> u64 {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let response = create(&app, draft()).await;
	response["created"]["e"]["size"].as_u64().expect("size")
}

/// The state of one test, with an API key of its own: a key is looked up by
/// hash, so requests at the same moment do not queue behind the password
/// hash of the configured token.
fn state(dir: &std::path::Path, limit: u64) -> Router {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("open key store");
	keys.add(crate::api::api_keys::ApiKey {
		grants: Vec::new(),
		label: "race".to_string(),
		hash: crate::api::api_keys::sha256_hash(KEY),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string(), "write".to_string()],
		domains: Vec::new(),
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
	drop(keys);
	router(test_state(dir, 0).with_quota(limit))
}

async fn call(app: &Router, call: Value) -> Value {
	let req = json!({"using": ["urn:ietf:params:jmap:mail"], "methodCalls": [call]});
	let (status, body) = request_with_body(app, "POST", "/jmap/api", Some(KEY), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

/// Run `REQUESTS` requests from one barrier; how many were admitted.
async fn burst(app: &Router, request: Value, key: &'static str) -> usize {
	let start = Arc::new(Barrier::new(REQUESTS));
	let mut set = tokio::task::JoinSet::new();
	for _ in 0..REQUESTS {
		let (app, request, start) = (app.clone(), request.clone(), start.clone());
		set.spawn(async move {
			start.wait().await;
			call(&app, request).await
		});
	}
	let mut admitted = 0;
	while let Some(answer) = set.join_next().await {
		let answer = answer.expect("request");
		if answer["created"][key]["id"].is_string() {
			admitted += 1;
		} else {
			assert_eq!(answer["notCreated"][key]["type"], "overQuota", "{answer}");
		}
	}
	admitted
}

fn usage(dir: &std::path::Path) -> u64 {
	crate::imap::mailbox::account_usage(dir, "alice", &crate::storage::MessageCrypto::disabled())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_set_create_at_the_same_moment_stops_at_the_quota() {
	let size = draft_size().await;
	let limit = size * FITS as u64 + size / 2;
	for round in 0..ROUNDS {
		let dir = tempfile::tempdir().expect("tempdir");
		std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
		let app = state(dir.path(), limit);
		let request = json!(["Email/set", {"accountId": "alice", "create": {"e": draft()}}, "c1"]);
		let admitted = burst(&app, request, "e").await;
		assert_eq!(admitted, FITS, "round {round}");
		assert!(usage(dir.path()) <= limit, "round {round}");
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_copy_at_the_same_moment_stops_at_the_quota() {
	let size = draft_size().await;
	// The source message plus `FITS` copies fit.
	let limit = size * (FITS as u64 + 1) + size / 2;
	for round in 0..ROUNDS {
		let dir = tempfile::tempdir().expect("tempdir");
		std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
		let app = state(dir.path(), limit);
		let first = create(&app, draft()).await;
		let id = first["created"]["e"]["id"].as_str().expect("source id");
		let request = json!(["Email/copy", {
			"fromAccountId": "alice", "accountId": "alice",
			"create": {"c": {"id": id, "mailboxIds": {"INBOX": true}}}
		}, "c1"]);
		let admitted = burst(&app, request, "c").await;
		assert_eq!(admitted, FITS, "round {round}");
		assert!(usage(dir.path()) <= limit, "round {round}");
	}
}
