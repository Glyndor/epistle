//! `PushSubscription/get` and `/set` (RFC 8620 §7.2) are session-scoped: they
//! carry no `accountId`, so the account gate the other JMAP methods apply never
//! runs on them. A subscription belongs to the credential that created it
//! (RFC 8620 §7.2.1: only subscriptions created "using authentication
//! credentials for the same user" are returned), so these tests pin that one
//! caller can neither list nor touch another caller's subscriptions, and that
//! each caller is capped.

use super::router;
use super::tests::{TOKEN, request_with_body};
use crate::storage::FsSpool;
use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

pub(super) const ANN: &str = "ann-push-secret";
const BOB: &str = "bob-push-secret";
const OPS: &str = "ops-push-secret";

/// Two accounts, a key bound to each, and an unconfined admin key `ops`.
pub(super) fn push_state(dir: &std::path::Path) -> Router {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	for (label, secret, account) in [
		("ann-key", ANN, Some("ann")),
		("bob-key", BOB, Some("bob")),
		("ops", OPS, None),
	] {
		key_store
			.add(crate::api::api_keys::ApiKey {
				label: label.to_string(),
				hash: crate::api::api_keys::sha256_hash(secret),
				expires_at: None,
				ip_cidr: None,
				scopes: vec!["read".to_string(), "write".to_string()],
				domains: Vec::new(),
				account: account.map(str::to_string),
			})
			.expect("add key");
	}
	drop(key_store);
	let account = |name: &str, address: &str| crate::config::Account {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let domains = vec!["example.org".to_string()];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![
				account("ann", "ann@example.org"),
				account("bob", "bob@example.org"),
			],
		)
		.expect("open store"),
	);
	let state = crate::api::ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle());
	router(state)
}

/// Run one method call as `token` and return its `[name, args, id]` triple.
pub(super) async fn call(app: &Router, token: &str, name: &str, args: Value) -> Value {
	let body = json!({ "methodCalls": [[name, args, "c1"]] });
	let (status, reply) =
		request_with_body(app, "POST", "/jmap/api", Some(token), Some(body)).await;
	assert_eq!(status, StatusCode::OK, "{reply}");
	reply["methodResponses"][0].clone()
}

/// Create one subscription as `token` and return its id.
pub(super) async fn create(app: &Router, token: &str, url: &str) -> String {
	let reply = call(
		app,
		token,
		"PushSubscription/set",
		json!({ "create": { "s": { "deviceClientId": "d", "url": url } } }),
	)
	.await;
	reply[1]["created"]["s"]["id"]
		.as_str()
		.unwrap_or_else(|| panic!("not created: {}", reply[1]["notCreated"]))
		.to_string()
}

/// The ids `token` sees from `PushSubscription/get` with `ids`.
pub(super) async fn visible(app: &Router, token: &str, ids: Value) -> (Vec<String>, Value) {
	let reply = call(app, token, "PushSubscription/get", json!({ "ids": ids })).await;
	let list = reply[1]["list"]
		.as_array()
		.expect("list")
		.iter()
		.filter_map(|sub| sub["id"].as_str().map(str::to_string))
		.collect();
	(list, reply[1]["notFound"].clone())
}

#[tokio::test]
async fn another_caller_cannot_list_a_subscription() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	let id = create(&app, ANN, "https://push.example/ann").await;

	let (all, _) = visible(&app, BOB, Value::Null).await;
	assert!(all.is_empty(), "bob listed ann's subscription");
	let (named, not_found) = visible(&app, BOB, json!([id])).await;
	assert!(named.is_empty(), "bob fetched ann's subscription by id");
	assert_eq!(not_found, json!([id]));
	// An admin credential is a different caller too: the configured token and
	// the `ops` key each see only what they created.
	let admin = create(&app, TOKEN.as_str(), "https://push.example/admin").await;
	assert_eq!(
		visible(&app, TOKEN.as_str(), Value::Null).await.0,
		vec![admin]
	);
	assert!(
		visible(&app, OPS, Value::Null).await.0.is_empty(),
		"ops listed the token's"
	);

	assert_eq!(visible(&app, ANN, Value::Null).await.0, vec![id]);
}

#[tokio::test]
async fn another_caller_cannot_update_or_destroy_a_subscription() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	let id = create(&app, ANN, "https://push.example/ann").await;

	let reply = call(
		&app,
		BOB,
		"PushSubscription/set",
		json!({ "update": { (id.clone()): { "types": ["Mailbox"] } }, "destroy": [id] }),
	)
	.await;
	assert_eq!(reply[1]["notUpdated"][&id]["type"], "notFound", "{reply}");
	assert_eq!(reply[1]["notDestroyed"][&id]["type"], "notFound", "{reply}");
	assert_eq!(reply[1]["destroyed"], json!([]), "{reply}");
	assert_eq!(visible(&app, ANN, Value::Null).await.0, vec![id.clone()]);

	let reply = call(
		&app,
		ANN,
		"PushSubscription/set",
		json!({ "destroy": [id] }),
	)
	.await;
	assert_eq!(reply[1]["destroyed"], json!([id]), "{reply}");
	assert!(visible(&app, ANN, Value::Null).await.0.is_empty());
}

#[tokio::test]
async fn each_caller_is_capped_at_sixteen_subscriptions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	for n in 0..16 {
		create(&app, ANN, &format!("https://push.example/{n}")).await;
	}
	let reply = call(
		&app,
		ANN,
		"PushSubscription/set",
		json!({ "create": { "extra": { "deviceClientId": "d", "url": "https://push.example/x" } } }),
	)
	.await;
	assert_eq!(
		reply[1]["notCreated"]["extra"]["type"], "overQuota",
		"{reply}"
	);
	assert_eq!(visible(&app, ANN, Value::Null).await.0.len(), 16);
	// The cap is per caller: ann's sixteen do not use up bob's room.
	create(&app, BOB, "https://push.example/bob").await;
}
