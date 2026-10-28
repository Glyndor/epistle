//! Principal-gate tests for the credential details the principal has to
//! carry past the middleware: the client IP an `ip_cidr` key is pinned to.

use super::router;
use crate::storage::FsSpool;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// Two tenants (`ann` in `a.example`, `bob` in `b.example`) and the one
/// API key given.
pub(super) fn state_with_key(
	dir: &std::path::Path,
	key: crate::api::api_keys::ApiKey,
) -> crate::api::ApiState {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store.add(key).expect("add key");
	drop(key_store);
	let account = |name: &str, address: &str| crate::config::Account {
		display_name: None,
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
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
	crate::api::ApiState::new(
		&crate::smtp::auth::tests::base::hash(super::tests::TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle())
}

/// A key with the given reach, all three scopes and an optional CIDR pin.
pub(super) fn key(
	secret: &str,
	domains: &[&str],
	account: Option<&str>,
	ip_cidr: Option<&str>,
) -> crate::api::api_keys::ApiKey {
	crate::api::api_keys::ApiKey {
		label: "test-key".to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: ip_cidr.map(str::to_string),
		scopes: vec!["read".to_string(), "write".to_string(), "send".to_string()],
		domains: domains.iter().map(|d| (*d).to_string()).collect(),
		account: account.map(str::to_string),
	}
}

/// `POST /jmap/api` from `peer`, as the listener with `ConnectInfo` sees it.
async fn jmap_from(
	app: &Router,
	secret: &str,
	peer: &str,
	body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
	let addr: std::net::SocketAddr = peer.parse().expect("peer address");
	let request = Request::builder()
		.method("POST")
		.uri("/jmap/api")
		.header(header::AUTHORIZATION, format!("Bearer {secret}"))
		.header(header::CONTENT_TYPE, "application/json")
		.extension(ConnectInfo(addr))
		.body(Body::from(body.to_string()))
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
	)
}

/// A key pinned to an address keeps its write scope inside the JMAP
/// dispatcher: the per-method scope re-check must see the same client IP
/// the middleware matched the key with.
#[tokio::test]
async fn ip_pinned_key_keeps_its_write_scope_inside_jmap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = "pinned-secret";
	let state = state_with_key(
		dir.path(),
		key(secret, &["a.example"], None, Some("192.0.2.0/24")),
	);
	let app = router(state);
	let request = serde_json::json!({
		"methodCalls": [["Mailbox/set", {
			"accountId": "ann",
			"create": {"k1": {"name": "Projects"}},
		}, "m1"]],
	});
	let (status, body) = jmap_from(&app, secret, "192.0.2.7:40000", request).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[0], "Mailbox/set",
		"pinned key from its own network must pass the write re-check: {body}"
	);
	assert_eq!(response[1]["created"]["k1"]["id"], "Projects", "{body}");
}
