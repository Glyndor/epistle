//! Helpers the `SieveScript` tests share: an app, the store behind it, the
//! calls, and a second tenant for the cross-account cases.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use crate::managesieve::store::ScriptStore;
use crate::storage::FsSpool;

/// The script store of `account`, as ManageSieve opens it.
pub(super) fn store(dir: &std::path::Path, account: &str) -> ScriptStore {
	ScriptStore::new(&dir.join("accounts"), account)
}

pub(super) fn app(dir: &std::path::Path) -> Router {
	router(test_state(dir, 0))
}

/// One method call; the method response, `[name, arguments, callId]`.
pub(super) async fn call(app: &Router, token: &str, method: &str, args: Value) -> Value {
	let request = json!({ "methodCalls": [[method, args, "c1"]] });
	let (_, body) = request_with_body(app, "POST", "/jmap/api", Some(token), Some(request)).await;
	body["methodResponses"][0].clone()
}

pub(super) async fn call_as_alice(app: &Router, method: &str, args: Value) -> Value {
	call(app, TOKEN.as_str(), method, args).await
}

/// `GET` of a download URL: the status, the content type and the octets.
pub(super) async fn download(
	app: &Router,
	token: &str,
	path: &str,
) -> (u16, Option<String>, Vec<u8>) {
	let request = Request::builder()
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.body(Body::empty())
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status().as_u16();
	let content_type = response
		.headers()
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.map(str::to_string);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, content_type, bytes.to_vec())
}

/// `ann` and `bob` on separate domains, and a key bound to `ann` alone with
/// the given scopes.
pub(super) fn ann_only(dir: &std::path::Path, scopes: &[&str]) -> (Router, String) {
	let secret = crate::test_fixtures::api_key().to_string();
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("open key store");
	keys.add(crate::api::api_keys::ApiKey {
		label: "ann-only".to_string(),
		hash: crate::api::api_keys::sha256_hash(&secret),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
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

/// Upload `body` into `account`'s blob store, as a client does before it
/// refers to the blob: the blob id.
pub(super) async fn upload(app: &Router, token: &str, account: &str, body: &[u8]) -> String {
	let request = Request::builder()
		.method("POST")
		.uri(format!("/jmap/upload/{account}"))
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.header(header::CONTENT_TYPE, "application/sieve")
		.body(Body::from(body.to_vec()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	assert_eq!(response.status().as_u16(), 200, "the upload is accepted");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json: Value = serde_json::from_slice(&bytes).expect("json");
	json["blobId"].as_str().expect("blobId").to_string()
}
